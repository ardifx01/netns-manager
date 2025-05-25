# netns-manager: Network Namespace and NAT Management Tool

`netns-manager` is a command-line interface (CLI) tool written in Go to simplify the management of Linux network namespaces and basic NAT MASQUERADE rules using `iptables`. It acts as a wrapper around `ip netns` and `iptables` commands, providing a structured interface for common operations.

**This tool requires root privileges (or `sudo`) for most of its operations.**

## Table of Contents

- [netns-manager: Network Namespace and NAT Management Tool](#netns-manager-network-namespace-and-nat-management-tool)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [General Usage](#general-usage)
  - [Command Reference](#command-reference)
    - [Network Namespace Commands](#network-namespace-commands)
      - [`netns-manager add`](#netns-manager-add)
      - [`netns-manager list`](#netns-manager-list)
      - [`netns-manager delete`](#netns-manager-delete)
      - [`netns-manager exists`](#netns-manager-exists)
      - [`netns-manager exec`](#netns-manager-exec)
    - [Network Interface Commands](#network-interface-commands)
      - [`netns-manager network add`](#netns-manager-network-add)
      - [`netns-manager network delete`](#netns-manager-network-delete)
      - [`netns-manager network enable`](#netns-manager-network-enable)
      - [`netns-manager network disable`](#netns-manager-network-disable)
    - [Masquerade (NAT) Commands](#masquerade-nat-commands)
      - [`netns-manager masquerade enable`](#netns-manager-masquerade-enable)
      - [`netns-manager masquerade disable`](#netns-manager-masquerade-disable)
  - [Important Notes](#important-notes)
  - [IP Address Assignment](#ip-address-assignment)

## Prerequisites

*   **Linux Operating System:** Network namespaces and `iptables` are Linux-specific features.
*   **Go:** Version 1.16 or higher (for building from source).
*   **`iproute2` package:** Provides the `ip` command (usually pre-installed).
*   **`iptables` package:** Provides the `iptables` command (usually pre-installed).
*   **Root Privileges:** Most operations require `sudo`.

## Building from Source

1.  **Clone the repository or save the `main.go` file.**
    If you have the `main.go` file:
    ```bash
    # Ensure you have Go installed
    # Create a project directory (optional but good practice)
    mkdir netns-manager-project
    cd netns-manager-project
    # If you haven't already, initialize go modules
    # go mod init myproject/netns-manager
    # go get -u github.com/spf13/cobra@latest # If not already in go.mod
    # Place main.go in this directory
    ```

2.  **Build the executable:**
    ```bash
    go build -o netns-manager .
    ```
    This will create an executable file named `netns-manager` in the current directory. You can move this to a directory in your `$PATH` (e.g., `/usr/local/bin`) for system-wide access:
    ```bash
    sudo mv netns-manager /usr/local/bin/
    ```

## General Usage

All commands that modify the system state or query certain system information require root privileges. Always run `netns-manager` with `sudo`:

```bash
sudo netns-manager [command] [subcommand] [arguments...]
```

To get help for any command:
```bash
sudo netns-manager help
sudo netns-manager [command] --help
sudo netns-manager [command] [subcommand] --help
```

## Command Reference

### Network Namespace Commands

These commands manage network namespaces.

#### `netns-manager add`

Adds a new network namespace with optional network interface configuration.

*   **Usage:** `sudo netns-manager add <namespace_name> [flags]`
*   **Arguments:**
    *   `<namespace_name>`: The desired name for the new network namespace.
*   **Flags:**
    *   `--no-interface, -n`: Skip automatic interface creation
    *   `--ip, -i`: Manually specify IP address in CIDR format (e.g., 10.0.1.100/24)
*   **Features:**
    * Automatically brings up the loopback interface
    * Creates and configures a virtual ethernet (veth) pair by default
    * Automatically assigns IP addresses in format 10.0.<instance_id>.<increment>
    * Instance ID is extracted from the first number in namespace name
    * Increment is automatically managed to avoid IP conflicts
*   **Examples:**
    ```bash
    # Create namespace with automatic interface and IP
    sudo netns-manager add app_1
    # Output: Network namespace 'app_1' created with IP 10.0.1.1/24

    # Create namespace with manual IP
    sudo netns-manager add app_1 --ip 10.0.1.100/24
    # Output: Network namespace 'app_1' created with IP 10.0.1.100/24

    # Create namespace without interface
    sudo netns-manager add app_1 --no-interface
    # Output: Network namespace 'app_1' created (no interface)
    ```

#### `netns-manager list`

Lists all existing network namespaces along with their IP configuration.

*   **Usage:** `sudo netns-manager list`
*   **Example:**
    ```bash
    sudo netns-manager list
    # Output:
    # Network Namespaces:
    #
    # my_app_ns:
    #   lo (DOWN): 
    #   eth0 (UP): 192.168.100.2/24
    #
    # another_ns:
    #   lo (DOWN):
    #   veth0 (UP): 10.0.1.5/24
    ```

#### `netns-manager delete`

Deletes an existing network namespace.

*   **Usage:** `sudo netns-manager delete <namespace_name>`
*   **Arguments:**
    *   `<namespace_name>`: The name of the network namespace to delete.
*   **Example:**
    ```bash
    sudo netns-manager delete my_app_ns
    # Output: Network namespace 'my_app_ns' deleted successfully.
    ```

#### `netns-manager exists`

Checks if a network namespace exists. Exits with status `0` if it exists, `1` if it does not, and `2` if there was an error checking.

*   **Usage:** `sudo netns-manager exists <namespace_name>`
*   **Arguments:**
    *   `<namespace_name>`: The name of the network namespace to check.
*   **Example:**
    ```bash
    sudo netns-manager exists my_app_ns
    # Output (if exists): Network namespace 'my_app_ns' exists.
    # echo $?  # Output: 0

    sudo netns-manager exists non_existent_ns
    # Output (if not exists): Network namespace 'non_existent_ns' does not exist.
    # echo $?  # Output: 1
    ```

#### `netns-manager exec`

Executes a command within a specified network namespace.

*   **Usage:** `sudo netns-manager exec <namespace_name> -- <command> [command_args...]`
*   **Arguments:**
    *   `<namespace_name>`: The network namespace to execute the command in.
    *   `--`: A separator indicating that subsequent arguments are for the command to be executed, not for `netns-manager`.
    *   `<command>`: The command to execute.
    *   `[command_args...]`: Arguments for the command.
*   **Example:**
    ```bash
    sudo netns-manager add test_ns
    sudo netns-manager exec test_ns -- ip link show lo
    # Output: (ip link output for 'lo' interface inside test_ns)

    sudo netns-manager exec test_ns -- ping -c 1 127.0.0.1
    # Output: (ping output from within test_ns)

    sudo netns-manager exec test_ns -- bash
    # (This will open an interactive bash shell inside the test_ns namespace)
    ```

### Network Interface Commands

These commands manage network interfaces within namespaces.

#### `netns-manager network add`

Creates a new network interface in a namespace with automatic IP assignment and DNS configuration.

*   **Usage:** `sudo netns-manager network add <app_key> [ending]`
*   **Arguments:**
    *   `<app_key>`: The base name for the namespace (e.g., "app")
    *   `[ending]`: Optional numeric ending. If not provided, auto-increments based on existing namespaces
*   **Features:**
    * Creates namespace if it doesn't exist (format: <app_key>_<ending>)
    * Configures veth pair with host and namespace ends
    * Sets up proper routing for internet access
    * Configures DNS resolution using Google DNS (8.8.8.8, 8.8.4.4)
    * Host interface gets 10.0.<instance_id>.1/24
    * Namespace interface gets 10.0.<instance_id>.2/24
*   **Example:**
    ```bash
    # Create with auto-incrementing ending
    sudo netns-manager network add app
    # Output: Network interface created in namespace 'app_1' with IP 10.0.1.2/24

    # Create with specific ending
    sudo netns-manager network add app 2
    # Output: Network interface created in namespace 'app_2' with IP 10.0.2.2/24
    ```

#### `netns-manager network delete`

Deletes a network interface and its associated namespace.

*   **Usage:** `sudo netns-manager network delete <app_key> <ending>`
*   **Arguments:**
    *   `<app_key>`: The base name of the namespace
    *   `<ending>`: The numeric ending of the namespace
*   **Features:**
    * Removes the namespace and all its interfaces
    * Cleans up associated veth pairs on the host
*   **Example:**
    ```bash
    sudo netns-manager network delete app 1
    # Output: Network namespace 'app_1' and its interfaces deleted successfully.
    ```

#### `netns-manager network enable`

Enables (brings up) a network interface within a namespace.

*   **Usage:** `sudo netns-manager network enable <namespace_name> <interface_name>`
*   **Arguments:**
    *   `<namespace_name>`: The name of the network namespace
    *   `<interface_name>`: The name of the interface to enable
*   **Example:**
    ```bash
    sudo netns-manager network enable app_1 veth1
    # Output: Network interface 'veth1' in namespace 'app_1' enabled successfully.
    ```

#### `netns-manager network disable`

Disables (brings down) a network interface within a namespace.

*   **Usage:** `sudo netns-manager network disable <namespace_name> <interface_name>`
*   **Arguments:**
    *   `<namespace_name>`: The name of the network namespace
    *   `<interface_name>`: The name of the interface to disable
*   **Example:**
    ```bash
    sudo netns-manager network disable app_1 veth1
    # Output: Network interface 'veth1' in namespace 'app_1' disabled successfully.
    ```

### Masquerade (NAT) Commands

These commands manage `iptables` MASQUERADE rules for Network Address Translation (NAT). This is commonly used to allow processes within a private network namespace to access external networks (like the internet) using the host's IP address.

**Important:** For NAT to function, IP forwarding must be enabled in the kernel:
`sudo sysctl -w net.ipv4.ip_forward=1`
To make this persistent, add `net.ipv4.ip_forward=1` to `/etc/sysctl.conf` or a file in `/etc/sysctl.d/`.

#### `netns-manager masquerade enable`

Enables (adds) an `iptables` MASQUERADE rule in the `nat` table's `POSTROUTING` chain. The command now supports using either a subnet directly or a network namespace name. This command is idempotent; it will not add a duplicate rule if one already exists.

*   **Usage:** 
    - `sudo netns-manager masquerade enable <source_subnet> <outgoing_interface>`
    - `sudo netns-manager masquerade enable <namespace_name> <outgoing_interface>`
*   **Arguments:**
    *   `<source_subnet>|<namespace_name>`: Either:
        - The source IP address range (e.g., `10.0.1.0/24`) for which traffic should be masqueraded
        - The name of a network namespace (the command will automatically use its IP subnet)
    *   `<outgoing_interface>`: The host's network interface through which the masqueraded traffic will exit (e.g., `eth0`, `wlan0`).
*   **Examples:**
    ```bash
    # Using subnet directly
    sudo netns-manager masquerade enable 192.168.50.0/24 eth0
    # Output: MASQUERADE rule for subnet '192.168.50.0/24' via interface 'eth0' enabled successfully.

    # Using namespace name
    sudo netns-manager masquerade enable my_app_ns eth0
    # Output: MASQUERADE rule for subnet '192.168.100.2/24' via interface 'eth0' enabled successfully.
    # Note: The actual subnet will depend on the namespace's IP configuration
    ```

#### `netns-manager masquerade disable`

Disables (deletes) an `iptables` MASQUERADE rule. Like the enable command, it supports using either a subnet or namespace name. This command is idempotent; it will report if the rule doesn't exist and take no action.

*   **Usage:** 
    - `sudo netns-manager masquerade disable <source_subnet> <outgoing_interface>`
    - `sudo netns-manager masquerade disable <namespace_name> <outgoing_interface>`
*   **Arguments:**
    *   `<source_subnet>|<namespace_name>`: Either:
        - The source IP address range of the rule to delete
        - The name of a network namespace whose IP subnet rule should be deleted
    *   `<outgoing_interface>`: The outgoing interface of the rule to delete.
*   **Examples:**
    ```bash
    # Using subnet directly
    sudo netns-manager masquerade disable 192.168.50.0/24 eth0
    # Output: MASQUERADE rule for subnet '192.168.50.0/24' via interface 'eth0' disabled successfully.

    # Using namespace name
    sudo netns-manager masquerade disable my_app_ns eth0
    # Output: MASQUERADE rule for subnet '192.168.100.2/24' via interface 'eth0' disabled successfully.
    ```

## Important Notes

*   **Root Privileges:** Nearly all operations require `sudo` as they modify system-level network configurations.
*   **IP Forwarding for NAT:** For MASQUERADE rules to work, ensure `net.ipv4.ip_forward=1` is set in your kernel's sysctl settings.
*   **DNS Configuration:** Network namespaces are automatically configured with Google DNS servers (8.8.8.8, 8.8.4.4) for reliable DNS resolution.
*   **Routing Setup:** The tool automatically configures proper routing in namespaces for internet access.
*   **Host Interface:** For each namespace, a corresponding interface is created on the host with IP 10.0.<instance_id>.1/24.
*   **Idempotency:** All commands are designed to be idempotent, checking for existing configurations before making changes.
*   **Error Handling:** The tool provides basic error messages from the underlying `ip` and `iptables` commands.
*   **Persistence:** Network namespaces and their configurations persist until explicitly deleted or system reboot.

## IP Address Assignment

Network interfaces are assigned IPs in pairs:

* Host interface (veth0): `10.0.<instance_id>.1/24`
* Namespace interface (veth1): `10.0.<instance_id>.2/24`

Where `instance_id` is:
* For `network add`: The ending number (provided or auto-incremented)
* For regular `add`: First number found in namespace name

Examples:
* `network add app 1`:
  * Host: 10.0.1.1/24
  * Namespace (app_1): 10.0.1.2/24
* `network add app 2`:
  * Host: 10.0.2.1/24
  * Namespace (app_2): 10.0.2.2/24

This paired addressing scheme ensures proper routing between host and namespace interfaces.

