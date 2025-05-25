package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

// Package level variables and command definitions
var (
	skipInterface bool
	manualIP     string
	rootCmd      *cobra.Command
)

var networkAddCmd = &cobra.Command{
	Use:   "add <app_key> [ending]",
	Short: "Add a new network interface with automatic IP assignment",
	Long:  `Add a new network interface to a namespace with the given app key and optional ending number.`,
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		appKey := args[0]
		var nsName string
		var ending string

		// If no ending is provided, use the app key as the namespace name
		if len(args) > 1 {
			ending = args[1]
			nsName = fmt.Sprintf("%s_%s", appKey, ending)
		} else {
			nsName = appKey
			// Extract number from app key for IP assignment
			ending = ""
			for _, r := range appKey {
				if unicode.IsDigit(r) {
					ending += string(r)
				}
			}
			if ending == "" {
				ending = "1"
			}
		}

		// Check if namespace exists
		stdout, _, err := runIPCommand("ip", "netns", "list")
		exists := false
		if stdout != "" {
			namespaces := strings.Split(strings.TrimSpace(stdout), "\n")
			for _, ns := range namespaces {
				if ns != "" && strings.Fields(ns)[0] == nsName {
					exists = true
					break
				}
			}
		}

		if !exists {
			// Create namespace if it doesn't exist
			_, stderr, err := runIPCommand("ip", "netns", "add", nsName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating namespace '%s': %v\n", nsName, err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}

			// Set up DNS configuration
			if err := setupDNS(nsName); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to set up DNS: %v\n", err)
			}

			// Bring up loopback interface
			_, stderr, err = runIPCommand("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to bring up loopback interface: %v\n", err)
			}
		}

		// Create veth pair
		veth0 := fmt.Sprintf("veth0_%s", nsName)
		veth1 := fmt.Sprintf("veth1_%s", nsName)
		
		_, stderr, err := runIPCommand("ip", "link", "add", veth0, "type", "veth", "peer", "name", veth1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating veth pair: %v\n", err)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
			}
			os.Exit(1)
		}

		// Move veth1 to namespace
		_, stderr, err = runIPCommand("ip", "link", "set", veth1, "netns", nsName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error moving interface to namespace: %v\n", err)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
			}
			os.Exit(1)
		}

		// Get instance ID from namespace name
		instanceID := 1
		re := regexp.MustCompile(`\d+`)
		if matches := re.FindStringSubmatch(nsName); len(matches) > 0 {
			if id, err := strconv.Atoi(matches[0]); err == nil {
				instanceID = id
			}
		}

		// Set IP addresses according to convention
		hostIP := fmt.Sprintf("10.0.%d.1/24", instanceID)
		nsIP := fmt.Sprintf("10.0.%d.2/24", instanceID)

		// Configure host interface
		_, stderr, err = runIPCommand("ip", "addr", "add", hostIP, "dev", veth0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring host IP: %v\n", err)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
			}
			os.Exit(1)
		}

		// Configure namespace interface
		_, stderr, err = runIPCommand("ip", "netns", "exec", nsName, "ip", "addr", "add", nsIP, "dev", veth1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring namespace IP: %v\n", err)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
			}
			os.Exit(1)
		}

		// Print success message
		fmt.Printf("Network namespace '%s' created with IP %s\n", nsName, nsIP)
	},
}

var networkDeleteCmd = &cobra.Command{
	Use:   "delete <app_key> <ending>",
	Short: "Delete a network interface and its namespace",
	Long:  `Delete a network interface and its associated namespace based on the app key and ending number.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		appKey := args[0]
		ending := args[1]
		nsName := fmt.Sprintf("%s_%s", appKey, ending)

		// Delete the namespace (this will also delete all interfaces in it)
		_, stderr, err := runIPCommand("ip", "netns", "delete", nsName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting namespace '%s': %v\n", nsName, err)
			if stderr != "" {
				fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
			}
			os.Exit(1)
		}

		// Try to clean up the host-side veth interface if it exists
		veth0 := fmt.Sprintf("veth0_%s", nsName)
		runIPCommand("ip", "link", "delete", veth0)

		fmt.Printf("Network namespace '%s' and its interfaces deleted successfully.\n", nsName)
	},
}

// --- Helper Function to run ip netns commands ---
func runIPCommand(commandName string, args ...string) (string, string, error) {
	cmdArgs := args
	if commandName == "ip" && len(args) > 0 && args[0] != "netns" && args[0] != "link" && args[0] != "addr" && args[0] != "route" {
		// Prepend "netns" if it's an ip netns specific subcommand and not already there
		// This logic might need refinement based on actual ip subcommands used
		// For now, assuming if first arg is not link/addr/route, it's for netns
		// This was specific to the original runIPNetnsCommand, let's make it more generic
		// For iptables, commandName will be "iptables"
	}
	cmd := exec.Command(commandName, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Helper to build the common part of the iptables rule arguments for MASQUERADE
func getMasqueradeRuleArgs(sourceSubnet, outgoingInterface string) []string {
	return []string{"-s", sourceSubnet, "-o", outgoingInterface, "-j", "MASQUERADE"}
}

// --- Cobra Command Definitions ---

func init() {
	rootCmd = &cobra.Command{
		Use:   "netns-manager",
		Short: "A CLI tool to manage Linux network namespaces and related networking",
		Long: `netns-manager simplifies creating, listing, deleting,
executing commands within network namespaces, and managing basic NAT rules.
Requires root privileges (run with sudo).`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if os.Geteuid() != 0 {
				fmt.Println("This program must be run as root (or with sudo).")
				// Constructing example usage more dynamically
				var commandPath []string
				currentCmd := cmd
				for currentCmd.HasParent() && currentCmd.Parent() != rootCmd {
					commandPath = append([]string{currentCmd.Name()}, commandPath...)
					currentCmd = currentCmd.Parent()
				}
				commandPath = append([]string{currentCmd.Name()}, commandPath...)


				fmt.Printf("Example: sudo %s %s", os.Args[0], strings.Join(commandPath, " "))
				if cmd.Flags().NFlag() > 0 || len(args) > 0 {
					fmt.Print(" [args/flags...]")
				}
				fmt.Println()
				os.Exit(1)
			}
		},
	}

	// --- Network Namespace Commands (existing) ---
	var addCmd = &cobra.Command{
		Use:   "add <namespace_name>",
		Short: "Add a new network namespace with optional interface",
		Long:  `Add a new network namespace and optionally configure a network interface with automatic IP assignment in format 10.0.<instance_id>.<increment>`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			_, stderr, err := runIPCommand("ip", "netns", "add", nsName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error adding namespace '%s': %v\n", nsName, err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}

			// Bring up the loopback interface automatically
			_, stderr, err = runIPCommand("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to bring up loopback interface: %v\n", err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
			}

			if !skipInterface {
				// Define veth interface names
				veth0 := fmt.Sprintf("veth0_%s", nsName)
				veth1 := fmt.Sprintf("veth1_%s", nsName)

				// Parse instance ID from name (assuming format contains a number)
				instanceID := 1
				re := regexp.MustCompile(`\d+`)
				if matches := re.FindStringSubmatch(nsName); len(matches) > 0 {
					if id, err := strconv.Atoi(matches[0]); err == nil {
						instanceID = id
					}
				}

				// Set IP addresses according to convention
				hostIP := fmt.Sprintf("10.0.%d.1/24", instanceID)
				nsIP := fmt.Sprintf("10.0.%d.2/24", instanceID)

				// Create veth pair
				_, stderr, err = runIPCommand("ip", "link", "add", veth0, "type", "veth", "peer", "name", veth1)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating veth pair: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				// Move veth1 to namespace
				_, stderr, err = runIPCommand("ip", "link", "set", veth1, "netns", nsName)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error configuring namespace IP: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				// Configure host interface
				_, stderr, err = runIPCommand("ip", "addr", "add", hostIP, "dev", veth0)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error configuring host IP: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				// Configure namespace interface
				_, stderr, err = runIPCommand("ip", "netns", "exec", nsName, "ip", "addr", "add", nsIP, "dev", veth1)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error configuring namespace IP: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				// Bring up the interfaces
				_, stderr, err = runIPCommand("ip", "netns", "exec", nsName, "ip", "link", "set", veth1, "up")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error bringing up interface in namespace: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				_, stderr, err = runIPCommand("ip", "link", "set", veth0, "up")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error bringing up host interface: %v\n", err)
					if stderr != "" {
						fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
					}
					os.Exit(1)
				}

				fmt.Printf("Network namespace '%s' created with IP %s\n", nsName, nsIP)
			} else {
				fmt.Printf("Network namespace '%s' created (no interface)\n", nsName)
			}
		},
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all network namespaces with their IP addresses",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			stdout, stderr, err := runIPCommand("ip", "netns", "list")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listing namespaces: %v\n", err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}
			if stdout == "" {
				fmt.Println("No network namespaces found.")
				return
			}

			fmt.Println("Network Namespaces:")
			// Parse the namespaces, removing any "(id: X)" suffixes
			namespaces := strings.Split(strings.TrimSpace(stdout), "\n")
			for _, ns := range namespaces {
				nsName := strings.Fields(ns)[0] // Get just the name part
				fmt.Printf("\n%s:\n", nsName)
				
				// Get IP addresses for this namespace
				ipArgs := []string{"netns", "exec", nsName, "ip", "-br", "addr"}
				ipOut, ipErr, err := runIPCommand("ip", ipArgs...)
				if err != nil {
					fmt.Printf("  Error getting IP addresses: %v\n", err)
					if ipErr != "" {
						fmt.Printf("  Error details: %s\n", ipErr)
					}
					continue
				}
				
				if ipOut == "" {
					fmt.Println("  No IP addresses configured")
					continue
				}

				// Format and display IP information
				interfaces := strings.Split(strings.TrimSpace(ipOut), "\n")
				for _, iface := range interfaces {
					parts := strings.Fields(iface)
					if len(parts) >= 3 {
						ifname := parts[0]
						state := parts[1]
						addrs := parts[2:]
						fmt.Printf("  %s (%s): %s\n", ifname, state, strings.Join(addrs, ", "))
					} else if len(parts) > 0 {
						// If we have partial information, show what we have
						fmt.Printf("  %s: incomplete information\n", strings.Join(parts, " "))
					}
				}
			}
		},
	}

	var deleteCmd = &cobra.Command{
		Use:   "delete <namespace_name>",
		Short: "Delete a network namespace",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			_, stderr, err := runIPCommand("ip", "netns", "delete", nsName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting namespace '%s': %v\n", nsName, err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}
			fmt.Printf("Network namespace '%s' deleted successfully.\n", nsName)
		},
	}

	var existsCmd = &cobra.Command{
		Use:   "exists <namespace_name>",
		Short: "Check if a network namespace exists",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			stdout, _, err := runIPCommand("ip", "netns", "list")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking namespace existence (could not list namespaces): %v\n", err)
				os.Exit(2)
			}
			namespaces := strings.Fields(stdout)
			found := false
			for _, existingNs := range namespaces {
				if strings.HasPrefix(existingNs, nsName) &&
					(existingNs == nsName || strings.HasPrefix(existingNs, nsName+"(id:")) {
					found = true
					break
				}
			}
			if found {
				fmt.Printf("Network namespace '%s' exists.\n", nsName)
				os.Exit(0)
			} else {
				fmt.Printf("Network namespace '%s' does not exist.\n", nsName)
				os.Exit(1)
			}
		},
	}

	var execCmd = &cobra.Command{
		Use:   "exec <namespace_name> -- <command> [args...]",
		Short: "Execute a command within a network namespace",
		Long: `Execute a command within the specified network namespace.
Use '--' to separate netns-manager arguments from the command to be executed.
Example: netns-manager exec my_ns -- ip addr show`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			dashPos := -1
			for i, arg := range os.Args {
				if arg == "--" {
					dashPos = i
					break
				}
			}
			var commandToRun []string
			if dashPos != -1 && len(os.Args) > dashPos+1 {
				commandToRun = os.Args[dashPos+1:]
			} else if len(args) > 1 {
				fmt.Fprintln(os.Stderr, "Warning: For clarity with 'exec', please use '--' to separate the command.")
				commandToRun = args[1:]
			}

			if len(commandToRun) == 0 {
				fmt.Fprintln(os.Stderr, "Error: No command provided to execute in the namespace.")
				cmd.Usage()
				os.Exit(1)
			}

			ipArgs := []string{"netns", "exec", nsName}
			ipArgs = append(ipArgs, commandToRun...)

			execCmd := exec.Command("ip", ipArgs...)
			execCmd.Stdin = os.Stdin
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr
			err := execCmd.Run()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				} else {
					fmt.Fprintf(os.Stderr, "Error executing command in namespace '%s': %v\n", nsName, err)
					os.Exit(1)
				}
			}
		},
	}

	var bashCmd = &cobra.Command{
		Use:   "bash <namespace_name>",
		Short: "Start an interactive bash shell in the specified namespace",
		Long:  `Launch an interactive bash shell within the specified network namespace.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			
			// Check if namespace exists first
			stdout, _, err := runIPCommand("ip", "netns", "list")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking namespace existence: %v\n", err)
				os.Exit(1)
			}
			
			exists := false
			namespaces := strings.Fields(stdout)
			for _, ns := range namespaces {
				if strings.HasPrefix(ns, nsName) {
					exists = true
					break
				}
			}
			
			if !exists {
				fmt.Fprintf(os.Stderr, "Network namespace '%s' does not exist\n", nsName)
				os.Exit(1)
			}

			// Execute bash in the namespace
			bashCmd := exec.Command("ip", "netns", "exec", nsName, "bash")
			bashCmd.Stdin = os.Stdin
			bashCmd.Stdout = os.Stdout
			bashCmd.Stderr = os.Stderr
			
			err = bashCmd.Run()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				} else {
					fmt.Fprintf(os.Stderr, "Error executing bash in namespace '%s': %v\n", nsName, err)
					os.Exit(1)
				}
			}
		},
	}

	// --- Masquerade Command Definitions (New) ---
	var masqueradeCmd = &cobra.Command{
		Use:   "masquerade",
		Short: "Manage NAT MASQUERADE rules using iptables",
		Long: `Manage NAT MASQUERADE rules for specific subnets and outgoing interfaces.
Requires root privileges. Ensure 'net.ipv4.ip_forward=1' is set in sysctl for NAT to function.`,
	}

	var masqueradeEnableCmd = &cobra.Command{
		Use:   "enable (<source_subnet>|<namespace_name>) <outgoing_interface>",
		Short: "Enable (add) a MASQUERADE rule for a subnet or namespace",
		Long: `Adds an iptables MASQUERADE rule in the nat table's POSTROUTING chain.
Examples:
  netns-manager masquerade enable 10.0.1.0/24 eth0
  netns-manager masquerade enable my_namespace eth0
This command is idempotent; it won't add duplicate rules.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			sourceSubnet := args[0]
			outgoingInterface := args[1]

			// Check if the first argument is a namespace name
			stdout, _, _ := runIPCommand("ip", "netns", "list")
			namespaces := strings.Fields(stdout)
			for _, ns := range namespaces {
				if strings.HasPrefix(ns, sourceSubnet) {
					// It's a namespace name, get its subnet
					subnet, err := getNamespaceSubnet(sourceSubnet)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error getting subnet for namespace '%s': %v\n", sourceSubnet, err)
						os.Exit(1)
					}
					sourceSubnet = subnet
					break
				}
			}

			ruleArgs := getMasqueradeRuleArgs(sourceSubnet, outgoingInterface)

			// Check if the rule already exists
			checkArgs := append([]string{"-t", "nat", "-C", "POSTROUTING"}, ruleArgs...)
			_, _, errCheck := runIPCommand("iptables", checkArgs...)

			if errCheck == nil {
				fmt.Printf("MASQUERADE rule for subnet '%s' via interface '%s' already exists.\n", sourceSubnet, outgoingInterface)
				return
			}

			// Add the rule if it doesn't exist
			addArgs := append([]string{"-t", "nat", "-A", "POSTROUTING"}, ruleArgs...)
			_, stderrAdd, errAdd := runIPCommand("iptables", addArgs...)

			if errAdd != nil {
				fmt.Fprintf(os.Stderr, "Error enabling MASQUERADE rule for subnet '%s' via interface '%s': %v\n", sourceSubnet, outgoingInterface, errAdd)
				if stderrAdd != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderrAdd)
				}
				os.Exit(1)
			}
			fmt.Printf("MASQUERADE rule for subnet '%s' via interface '%s' enabled successfully.\n", sourceSubnet, outgoingInterface)
			fmt.Println("Note: Ensure 'net.ipv4.ip_forward=1' is set in sysctl for NAT to work.")
		},
	}

	var masqueradeDisableCmd = &cobra.Command{
		Use:   "disable (<source_subnet>|<namespace_name>) <outgoing_interface>",
		Short: "Disable (delete) a MASQUERADE rule for a subnet or namespace",
		Long: `Deletes an iptables MASQUERADE rule from the nat table's POSTROUTING chain.
Examples:
  netns-manager masquerade disable 10.0.1.0/24 eth0
  netns-manager masquerade disable my_namespace eth0
This command is idempotent; it will report if the rule doesn't exist.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			sourceSubnet := args[0]
			outgoingInterface := args[1]

			// Check if the first argument is a namespace name
			stdout, _, _ := runIPCommand("ip", "netns", "list")
			namespaces := strings.Fields(stdout)
			for _, ns := range namespaces {
				if strings.HasPrefix(ns, sourceSubnet) {
					// It's a namespace name, get its subnet
					subnet, err := getNamespaceSubnet(sourceSubnet)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error getting subnet for namespace '%s': %v\n", sourceSubnet, err)
						os.Exit(1)
					}
					sourceSubnet = subnet
					break
				}
			}

			ruleArgs := getMasqueradeRuleArgs(sourceSubnet, outgoingInterface)

			// Check if the rule exists
			checkArgs := append([]string{"-t", "nat", "-C", "POSTROUTING"}, ruleArgs...)
			_, _, errCheck := runIPCommand("iptables", checkArgs...)

			if errCheck != nil {
				fmt.Printf("MASQUERADE rule for subnet '%s' via interface '%s' does not appear to exist. No action taken to delete.\n", sourceSubnet, outgoingInterface)
				return
			}

			// Delete the rule if it exists
			deleteArgs := append([]string{"-t", "nat", "-D", "POSTROUTING"}, ruleArgs...)
			_, stderrDelete, errDelete := runIPCommand("iptables", deleteArgs...)

			if errDelete != nil {
				fmt.Fprintf(os.Stderr, "Error disabling MASQUERADE rule for subnet '%s' via interface '%s': %v\n", sourceSubnet, outgoingInterface, errDelete)
				if stderrDelete != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderrDelete)
				}
				os.Exit(1)
			}
			fmt.Printf("MASQUERADE rule for subnet '%s' via interface '%s' disabled successfully.\n", sourceSubnet, outgoingInterface)
		},
	}

	// --- Network Interface Commands ---
	var networkCmd = &cobra.Command{
		Use:   "network",
		Short: "Manage network interfaces within namespaces",
		Long:  `Enable or disable network interfaces within network namespaces.`,
	}

	var networkEnableCmd = &cobra.Command{
		Use:   "enable <namespace_name> <interface_name>",
		Short: "Enable (bring up) a network interface in a namespace",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			ifName := args[1]

			// Set interface up
			_, stderr, err := runIPCommand("ip", "netns", "exec", nsName, "ip", "link", "set", ifName, "up")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error enabling interface '%s' in namespace '%s': %v\n", ifName, nsName, err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}
			fmt.Printf("Network interface '%s' in namespace '%s' enabled successfully.\n", ifName, nsName)
		},
	}

	var networkDisableCmd = &cobra.Command{
		Use:   "disable <namespace_name> <interface_name>",
		Short: "Disable (bring down) a network interface in a namespace",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			nsName := args[0]
			ifName := args[1]

			// Set interface down
			_, stderr, err := runIPCommand("ip", "netns", "exec", nsName, "ip", "link", "set", ifName, "down")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error disabling interface '%s' in namespace '%s': %v\n", ifName, nsName, err)
				if stderr != "" {
					fmt.Fprintf(os.Stderr, "Details: %s\n", stderr)
				}
				os.Exit(1)
			}
			fmt.Printf("Network interface '%s' in namespace '%s' disabled successfully.\n", ifName, nsName)
		},
	}

	// Add flags
	addCmd.Flags().BoolVarP(&skipInterface, "no-interface", "n", false, "Skip interface creation")
	addCmd.Flags().StringVarP(&manualIP, "ip", "i", "", "Manually specify IP address (CIDR format)")

	// Netns commands
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(existsCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(bashCmd)

	// Masquerade commands (New)
	rootCmd.AddCommand(masqueradeCmd)
	masqueradeCmd.AddCommand(masqueradeEnableCmd)
	masqueradeCmd.AddCommand(masqueradeDisableCmd)

	// Add network commands
	rootCmd.AddCommand(networkCmd)
	networkCmd.AddCommand(networkEnableCmd)
	networkCmd.AddCommand(networkDisableCmd)

	// Add network subcommands
	networkCmd.AddCommand(networkAddCmd)
	networkCmd.AddCommand(networkDeleteCmd)
}

// Helper function to get a namespace's IP subnet
func getNamespaceSubnet(nsName string) (string, error) {
	ipArgs := []string{"netns", "exec", nsName, "ip", "-br", "addr"}
	ipOut, _, err := runIPCommand("ip", ipArgs...)
	if err != nil {
		return "", fmt.Errorf("failed to get IP addresses for namespace %s: %v", nsName, err)
	}

	interfaces := strings.Split(strings.TrimSpace(ipOut), "\n")
	for _, iface := range interfaces {
		parts := strings.Fields(iface)
		if len(parts) >= 3 && parts[0] != "lo" {
			// Get the first non-loopback IP address
			for _, addr := range parts[2:] {
				if strings.Contains(addr, "/") && !strings.HasPrefix(addr, "127.") {
					return addr, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no suitable IP address found in namespace %s", nsName)
}

// Helper function to set up DNS in a namespace
func setupDNS(nsName string) error {
	// Read host's resolv.conf
	resolvContent, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("failed to read host resolv.conf: %v", err)
	}

	// Create /etc/netns/<namespace> directory if it doesn't exist
	netnsDir := fmt.Sprintf("/etc/netns/%s", nsName)
	if err := os.MkdirAll(netnsDir, 0755); err != nil {
		return fmt.Errorf("failed to create netns directory: %v", err)
	}

	// Write resolv.conf for the namespace
	nsResolvPath := fmt.Sprintf("%s/resolv.conf", netnsDir)
	if err := os.WriteFile(nsResolvPath, resolvContent, 0644); err != nil {
		return fmt.Errorf("failed to write namespace resolv.conf: %v", err)
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		// Cobra already prints the error, so this might be redundant
		// fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
