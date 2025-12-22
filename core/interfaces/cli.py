"""
Advanced Command-Line Interface for DDoS Testing Framework

This module provides a comprehensive CLI with:
- Intelligent auto-completion
- Interactive mode with real-time feedback
- Scripting support and batch operations
- Rich formatting and visualization
"""

import argparse
import asyncio
import cmd
import json
import os
import shlex
import sys
import time

# readline is not available on Windows by default
try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import logging

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich.live import Live
    from rich.layout import Layout
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)

class CLIConfig:
    """Configuration for CLI behavior and appearance"""
    def __init__(self):
        self.auto_complete = True
        self.color_output = True
        self.verbose_mode = False
        self.interactive_mode = False
        self.history_file = os.path.expanduser("~/.ddos_framework_history")
        self.script_timeout = 300  # 5 minutes
        self.max_history_size = 1000
        self.prompt_style = "ddos> "
        self.enable_suggestions = True

class CommandCompleter:
    """Intelligent auto-completion for CLI commands"""
    
    def __init__(self):
        self.commands = {
            'attack': {
                'subcommands': ['start', 'stop', 'status', 'list'],
                'options': ['--target', '--port', '--protocol', '--duration', '--processes']
            },
            'target': {
                'subcommands': ['analyze', 'resolve', 'profile', 'scan'],
                'options': ['--ip', '--url', '--timeout', '--deep-scan']
            },
            'config': {
                'subcommands': ['show', 'set', 'reset', 'export', 'import'],
                'options': ['--file', '--format', '--validate']
            },
            'monitor': {
                'subcommands': ['start', 'stop', 'dashboard', 'export'],
                'options': ['--interval', '--format', '--output']
            },
            'script': {
                'subcommands': ['run', 'validate', 'create', 'list'],
                'options': ['--file', '--timeout', '--parallel']
            },
            'help': {
                'subcommands': [],
                'options': ['--verbose', '--examples']
            }
        }
        
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ENTROPY']
        self.formats = ['json', 'yaml', 'csv', 'xml']
        
    def complete(self, text: str, line: str) -> List[str]:
        """Provide intelligent completions based on context"""
        tokens = shlex.split(line) if line else []
        
        if not tokens:
            return list(self.commands.keys())
        
        command = tokens[0]
        if command not in self.commands:
            return [cmd for cmd in self.commands.keys() if cmd.startswith(text)]
        
        # Complete subcommands
        if len(tokens) == 1 or (len(tokens) == 2 and not line.endswith(' ')):
            subcommands = self.commands[command]['subcommands']
            return [sub for sub in subcommands if sub.startswith(text)]
        
        # Complete options
        if text.startswith('--'):
            options = self.commands[command]['options']
            return [opt for opt in options if opt.startswith(text)]
        
        # Context-specific completions
        if '--protocol' in line:
            return [p for p in self.protocols if p.startswith(text.upper())]
        
        if '--format' in line:
            return [f for f in self.formats if f.startswith(text)]
        
        return []

class InteractiveMode(cmd.Cmd):
    """Interactive command-line interface with real-time feedback"""
    
    def __init__(self, cli_instance):
        super().__init__()
        self.cli = cli_instance
        self.console = Console() if RICH_AVAILABLE else None
        self.prompt = "ddos> "
        self.intro = self._get_intro_message()
        self.completer = CommandCompleter()
        self.current_attack = None
        self.monitoring_active = False
        
        # Setup readline for history and completion (if available)
        if READLINE_AVAILABLE and hasattr(readline, 'set_completer'):
            readline.set_completer(self._complete)
            readline.parse_and_bind('tab: complete')
            self._load_history()
    
    def _get_intro_message(self) -> str:
        """Generate welcome message for interactive mode"""
        if RICH_AVAILABLE:
            return ""  # Rich formatting handled separately
        else:
            return """
╔══════════════════════════════════════════════════════════════╗
║              DDoS Testing Framework - Interactive Mode       ║
║                                                              ║
║  Type 'help' for available commands                          ║
║  Type 'help <command>' for detailed command information      ║
║  Use Tab for auto-completion                                 ║
║  Type 'exit' or Ctrl+C to quit                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    def _complete(self, text: str, state: int) -> Optional[str]:
        """Completion function for readline"""
        if not READLINE_AVAILABLE:
            return None
        line = readline.get_line_buffer()
        completions = self.completer.complete(text, line)
        
        if state < len(completions):
            return completions[state]
        return None
    
    def _load_history(self):
        """Load command history from file"""
        if not READLINE_AVAILABLE:
            return
        try:
            if os.path.exists(self.cli.config.history_file):
                readline.read_history_file(self.cli.config.history_file)
        except Exception as e:
            logger.warning(f"Could not load history: {e}")
    
    def _save_history(self):
        """Save command history to file"""
        if not READLINE_AVAILABLE:
            return
        try:
            readline.set_history_length(self.cli.config.max_history_size)
            readline.write_history_file(self.cli.config.history_file)
        except Exception as e:
            logger.warning(f"Could not save history: {e}")
    
    def cmdloop(self, intro=None):
        """Enhanced command loop with rich formatting"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel.fit(
                "[bold blue]DDoS Testing Framework - Interactive Mode[/bold blue]\n\n"
                "Type [bold]help[/bold] for available commands\n"
                "Use [bold]Tab[/bold] for auto-completion\n"
                "Type [bold]exit[/bold] or [bold]Ctrl+C[/bold] to quit",
                title="Welcome",
                border_style="blue"
            ))
        
        try:
            super().cmdloop(intro)
        except KeyboardInterrupt:
            self.do_exit("")
        finally:
            self._save_history()
    
    def do_attack(self, args: str):
        """Attack management commands: start, stop, status, list"""
        if not args:
            self._show_attack_help()
            return
        
        parts = shlex.split(args)
        subcommand = parts[0] if parts else ""
        
        if subcommand == "start":
            self._start_attack(parts[1:])
        elif subcommand == "stop":
            self._stop_attack(parts[1:])
        elif subcommand == "status":
            self._show_attack_status()
        elif subcommand == "list":
            self._list_attacks()
        else:
            self._show_attack_help()
    
    def _start_attack(self, args: List[str]):
        """Start a new attack with specified parameters"""
        parser = argparse.ArgumentParser(prog="attack start", add_help=False)
        parser.add_argument('--target', required=True, help='Target IP or domain')
        parser.add_argument('--port', type=int, required=True, help='Target port')
        parser.add_argument('--protocol', required=True, choices=['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ENTROPY'])
        parser.add_argument('--duration', type=int, default=0, help='Attack duration in seconds')
        parser.add_argument('--processes', type=int, default=os.cpu_count(), help='Number of processes')
        
        try:
            parsed_args = parser.parse_args(args)
            
            if RICH_AVAILABLE and self.console:
                with self.console.status("[bold green]Starting attack..."):
                    result = self.cli.start_attack(parsed_args)
                
                if result['success']:
                    self.console.print(f"[green]✓[/green] Attack started successfully")
                    self.console.print(f"Session ID: {result['session_id']}")
                    self.current_attack = result['session_id']
                else:
                    self.console.print(f"[red]✗[/red] Attack failed: {result['error']}")
            else:
                print("Starting attack...")
                result = self.cli.start_attack(parsed_args)
                if result['success']:
                    print(f"✓ Attack started successfully")
                    print(f"Session ID: {result['session_id']}")
                    self.current_attack = result['session_id']
                else:
                    print(f"✗ Attack failed: {result['error']}")
                    
        except SystemExit:
            pass  # Argument parsing error
        except Exception as e:
            if RICH_AVAILABLE and self.console:
                self.console.print(f"[red]Error:[/red] {e}")
            else:
                print(f"Error: {e}")
    
    def _stop_attack(self, args: List[str]):
        """Stop an active attack"""
        session_id = args[0] if args else self.current_attack
        
        if not session_id:
            if RICH_AVAILABLE and self.console:
                self.console.print("[yellow]No active attack to stop[/yellow]")
            else:
                print("No active attack to stop")
            return
        
        result = self.cli.stop_attack(session_id)
        
        if RICH_AVAILABLE and self.console:
            if result['success']:
                self.console.print(f"[green]✓[/green] Attack {session_id} stopped")
            else:
                self.console.print(f"[red]✗[/red] Failed to stop attack: {result['error']}")
        else:
            if result['success']:
                print(f"✓ Attack {session_id} stopped")
            else:
                print(f"✗ Failed to stop attack: {result['error']}")
        
        if session_id == self.current_attack:
            self.current_attack = None
    
    def _show_attack_status(self):
        """Show status of current or all attacks"""
        status = self.cli.get_attack_status()
        
        if RICH_AVAILABLE and self.console:
            if not status['attacks']:
                self.console.print("[yellow]No active attacks[/yellow]")
                return
            
            table = Table(title="Attack Status")
            table.add_column("Session ID", style="cyan")
            table.add_column("Target", style="magenta")
            table.add_column("Protocol", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("PPS", justify="right")
            table.add_column("Duration", justify="right")
            
            for attack in status['attacks']:
                table.add_row(
                    attack['session_id'][:8] + "...",
                    f"{attack['target']}:{attack['port']}",
                    attack['protocol'],
                    attack['status'],
                    str(attack.get('pps', 0)),
                    str(attack.get('duration', 0))
                )
            
            self.console.print(table)
        else:
            if not status['attacks']:
                print("No active attacks")
                return
            
            print("\nActive Attacks:")
            print("-" * 80)
            for attack in status['attacks']:
                print(f"Session: {attack['session_id'][:8]}... | "
                      f"Target: {attack['target']}:{attack['port']} | "
                      f"Protocol: {attack['protocol']} | "
                      f"Status: {attack['status']}")
    
    def _list_attacks(self):
        """List all attacks (active and historical)"""
        attacks = self.cli.list_all_attacks()
        
        if RICH_AVAILABLE and self.console:
            table = Table(title="All Attacks")
            table.add_column("Session ID", style="cyan")
            table.add_column("Target", style="magenta")
            table.add_column("Protocol", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Started", style="blue")
            
            for attack in attacks:
                table.add_row(
                    attack['session_id'][:8] + "...",
                    f"{attack['target']}:{attack['port']}",
                    attack['protocol'],
                    attack['status'],
                    attack['started_at']
                )
            
            self.console.print(table)
        else:
            print("\nAll Attacks:")
            print("-" * 80)
            for attack in attacks:
                print(f"{attack['session_id'][:8]}... | "
                      f"{attack['target']}:{attack['port']} | "
                      f"{attack['protocol']} | "
                      f"{attack['status']} | "
                      f"{attack['started_at']}")
    
    def _show_attack_help(self):
        """Show help for attack commands"""
        help_text = """
Attack Commands:
  attack start --target <ip/domain> --port <port> --protocol <protocol> [options]
  attack stop [session_id]
  attack status
  attack list

Examples:
  attack start --target 192.168.1.100 --port 80 --protocol HTTP --duration 60
  attack stop abc123def
  attack status
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Attack Commands", border_style="blue"))
        else:
            print(help_text)
    
    def do_target(self, args: str):
        """Target analysis commands: analyze, resolve, profile, scan"""
        if not args:
            self._show_target_help()
            return
        
        parts = shlex.split(args)
        subcommand = parts[0] if parts else ""
        
        if subcommand == "analyze":
            self._analyze_target(parts[1:])
        elif subcommand == "resolve":
            self._resolve_target(parts[1:])
        elif subcommand == "profile":
            self._profile_target(parts[1:])
        elif subcommand == "scan":
            self._scan_target(parts[1:])
        else:
            self._show_target_help()
    
    def _analyze_target(self, args: List[str]):
        """Analyze target for optimal attack parameters"""
        if not args:
            if RICH_AVAILABLE and self.console:
                target = Prompt.ask("Enter target IP or domain")
            else:
                target = input("Enter target IP or domain: ")
        else:
            target = args[0]
        
        if RICH_AVAILABLE and self.console:
            with self.console.status(f"[bold green]Analyzing {target}..."):
                result = self.cli.analyze_target(target)
            
            if result['success']:
                self.console.print(Panel(
                    f"Target: {result['target']}\n"
                    f"IP: {result['ip']}\n"
                    f"Open Ports: {', '.join(map(str, result['open_ports']))}\n"
                    f"Services: {', '.join(result['services'])}\n"
                    f"Recommended Protocol: {result['recommended_protocol']}\n"
                    f"Optimal Packet Size: {result['optimal_packet_size']}",
                    title=f"Analysis Results for {target}",
                    border_style="green"
                ))
            else:
                self.console.print(f"[red]Analysis failed:[/red] {result['error']}")
        else:
            print(f"Analyzing {target}...")
            result = self.cli.analyze_target(target)
            if result['success']:
                print(f"\nAnalysis Results for {target}:")
                print(f"IP: {result['ip']}")
                print(f"Open Ports: {', '.join(map(str, result['open_ports']))}")
                print(f"Services: {', '.join(result['services'])}")
                print(f"Recommended Protocol: {result['recommended_protocol']}")
                print(f"Optimal Packet Size: {result['optimal_packet_size']}")
            else:
                print(f"Analysis failed: {result['error']}")
    
    def _resolve_target(self, args: List[str]):
        """Resolve domain to IP address"""
        if not args:
            if RICH_AVAILABLE and self.console:
                domain = Prompt.ask("Enter domain name")
            else:
                domain = input("Enter domain name: ")
        else:
            domain = args[0]
        
        result = self.cli.resolve_target(domain)
        
        if RICH_AVAILABLE and self.console:
            if result['success']:
                self.console.print(f"[green]{domain}[/green] resolves to [cyan]{result['ip']}[/cyan]")
            else:
                self.console.print(f"[red]Resolution failed:[/red] {result['error']}")
        else:
            if result['success']:
                print(f"{domain} resolves to {result['ip']}")
            else:
                print(f"Resolution failed: {result['error']}")
    
    def _profile_target(self, args: List[str]):
        """Create detailed target profile"""
        # Implementation for target profiling
        pass
    
    def _scan_target(self, args: List[str]):
        """Perform port scan on target"""
        # Implementation for port scanning
        pass
    
    def _show_target_help(self):
        """Show help for target commands"""
        help_text = """
Target Commands:
  target analyze <ip/domain>    - Analyze target for optimal attack parameters
  target resolve <domain>       - Resolve domain to IP address
  target profile <ip/domain>    - Create detailed target profile
  target scan <ip/domain>       - Perform port scan

Examples:
  target analyze google.com
  target resolve example.com
  target profile 192.168.1.1
  target scan 10.0.0.1
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Target Commands", border_style="blue"))
        else:
            print(help_text)
    
    def do_monitor(self, args: str):
        """Monitoring and dashboard commands"""
        if not args:
            self._show_monitor_help()
            return
        
        parts = shlex.split(args)
        subcommand = parts[0] if parts else ""
        
        if subcommand == "start":
            self._start_monitoring()
        elif subcommand == "stop":
            self._stop_monitoring()
        elif subcommand == "dashboard":
            self._show_dashboard()
        elif subcommand == "export":
            self._export_metrics(parts[1:])
        else:
            self._show_monitor_help()
    
    def _start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring_active:
            if RICH_AVAILABLE and self.console:
                self.console.print("[yellow]Monitoring already active[/yellow]")
            else:
                print("Monitoring already active")
            return
        
        self.monitoring_active = True
        if RICH_AVAILABLE and self.console:
            self.console.print("[green]✓[/green] Monitoring started")
        else:
            print("✓ Monitoring started")
    
    def _stop_monitoring(self):
        """Stop real-time monitoring"""
        if not self.monitoring_active:
            if RICH_AVAILABLE and self.console:
                self.console.print("[yellow]Monitoring not active[/yellow]")
            else:
                print("Monitoring not active")
            return
        
        self.monitoring_active = False
        if RICH_AVAILABLE and self.console:
            self.console.print("[green]✓[/green] Monitoring stopped")
        else:
            print("✓ Monitoring stopped")
    
    def _show_dashboard(self):
        """Show real-time dashboard"""
        if RICH_AVAILABLE and self.console:
            # Create a live dashboard
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3)
            )
            
            with Live(layout, refresh_per_second=2, screen=True):
                for i in range(30):  # Show for 30 seconds
                    # Update dashboard content
                    metrics = self.cli.get_real_time_metrics()
                    
                    layout["header"].update(Panel(
                        f"DDoS Framework Dashboard - {datetime.now().strftime('%H:%M:%S')}",
                        style="bold blue"
                    ))
                    
                    # Create metrics table
                    table = Table()
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", style="green")
                    
                    for key, value in metrics.items():
                        table.add_row(key, str(value))
                    
                    layout["body"].update(table)
                    layout["footer"].update(Panel("Press Ctrl+C to exit dashboard", style="dim"))
                    
                    time.sleep(0.5)
        else:
            print("Real-time dashboard (requires rich library)")
            for i in range(10):
                metrics = self.cli.get_real_time_metrics()
                print(f"\n--- Metrics ({datetime.now().strftime('%H:%M:%S')}) ---")
                for key, value in metrics.items():
                    print(f"{key}: {value}")
                time.sleep(1)
    
    def _export_metrics(self, args: List[str]):
        """Export metrics to file"""
        parser = argparse.ArgumentParser(prog="monitor export", add_help=False)
        parser.add_argument('--format', choices=['json', 'csv', 'yaml'], default='json')
        parser.add_argument('--output', default='metrics_export')
        
        try:
            parsed_args = parser.parse_args(args)
            result = self.cli.export_metrics(parsed_args.format, parsed_args.output)
            
            if RICH_AVAILABLE and self.console:
                if result['success']:
                    self.console.print(f"[green]✓[/green] Metrics exported to {result['filename']}")
                else:
                    self.console.print(f"[red]✗[/red] Export failed: {result['error']}")
            else:
                if result['success']:
                    print(f"✓ Metrics exported to {result['filename']}")
                else:
                    print(f"✗ Export failed: {result['error']}")
        except SystemExit:
            pass
    
    def _show_monitor_help(self):
        """Show help for monitor commands"""
        help_text = """
Monitor Commands:
  monitor start                 - Start real-time monitoring
  monitor stop                  - Stop monitoring
  monitor dashboard             - Show live dashboard
  monitor export [options]      - Export metrics to file

Examples:
  monitor start
  monitor dashboard
  monitor export --format csv --output my_metrics
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Monitor Commands", border_style="blue"))
        else:
            print(help_text)
    
    def do_script(self, args: str):
        """Script execution commands"""
        if not args:
            self._show_script_help()
            return
        
        parts = shlex.split(args)
        subcommand = parts[0] if parts else ""
        
        if subcommand == "run":
            self._run_script(parts[1:])
        elif subcommand == "validate":
            self._validate_script(parts[1:])
        elif subcommand == "create":
            self._create_script(parts[1:])
        elif subcommand == "list":
            self._list_scripts()
        else:
            self._show_script_help()
    
    def _run_script(self, args: List[str]):
        """Run a script file"""
        if not args:
            if RICH_AVAILABLE and self.console:
                script_file = Prompt.ask("Enter script filename")
            else:
                script_file = input("Enter script filename: ")
        else:
            script_file = args[0]
        
        if RICH_AVAILABLE and self.console:
            with self.console.status(f"[bold green]Running script {script_file}..."):
                result = self.cli.run_script(script_file)
            
            if result['success']:
                self.console.print(f"[green]✓[/green] Script completed successfully")
                self.console.print(f"Executed {result['commands_executed']} commands")
            else:
                self.console.print(f"[red]✗[/red] Script failed: {result['error']}")
        else:
            print(f"Running script {script_file}...")
            result = self.cli.run_script(script_file)
            if result['success']:
                print(f"✓ Script completed successfully")
                print(f"Executed {result['commands_executed']} commands")
            else:
                print(f"✗ Script failed: {result['error']}")
    
    def _validate_script(self, args: List[str]):
        """Validate script syntax"""
        # Implementation for script validation
        pass
    
    def _create_script(self, args: List[str]):
        """Create a new script interactively"""
        # Implementation for script creation
        pass
    
    def _list_scripts(self):
        """List available scripts"""
        scripts = self.cli.list_scripts()
        
        if RICH_AVAILABLE and self.console:
            if not scripts:
                self.console.print("[yellow]No scripts found[/yellow]")
                return
            
            table = Table(title="Available Scripts")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="green")
            table.add_column("Commands", justify="right")
            table.add_column("Modified", style="blue")
            
            for script in scripts:
                table.add_row(
                    script['name'],
                    script['description'],
                    str(script['command_count']),
                    script['modified']
                )
            
            self.console.print(table)
        else:
            if not scripts:
                print("No scripts found")
                return
            
            print("\nAvailable Scripts:")
            print("-" * 60)
            for script in scripts:
                print(f"{script['name']} - {script['description']} "
                      f"({script['command_count']} commands)")
    
    def _show_script_help(self):
        """Show help for script commands"""
        help_text = """
Script Commands:
  script run <filename>         - Run a script file
  script validate <filename>    - Validate script syntax
  script create <filename>      - Create new script interactively
  script list                   - List available scripts

Examples:
  script run my_attack.ddos
  script validate test_script.ddos
  script create new_attack.ddos
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Script Commands", border_style="blue"))
        else:
            print(help_text)
    
    def do_config(self, args: str):
        """Configuration management commands"""
        if not args:
            self._show_config_help()
            return
        
        parts = shlex.split(args)
        subcommand = parts[0] if parts else ""
        
        if subcommand == "show":
            self._show_config()
        elif subcommand == "set":
            self._set_config(parts[1:])
        elif subcommand == "reset":
            self._reset_config()
        elif subcommand == "export":
            self._export_config(parts[1:])
        elif subcommand == "import":
            self._import_config(parts[1:])
        else:
            self._show_config_help()
    
    def _show_config(self):
        """Show current configuration"""
        config = self.cli.get_config()
        
        if RICH_AVAILABLE and self.console:
            table = Table(title="Current Configuration")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in config.items():
                table.add_row(key, str(value))
            
            self.console.print(table)
        else:
            print("\nCurrent Configuration:")
            print("-" * 40)
            for key, value in config.items():
                print(f"{key}: {value}")
    
    def _set_config(self, args: List[str]):
        """Set configuration value"""
        if len(args) < 2:
            if RICH_AVAILABLE and self.console:
                self.console.print("[red]Usage:[/red] config set <key> <value>")
            else:
                print("Usage: config set <key> <value>")
            return
        
        key, value = args[0], args[1]
        result = self.cli.set_config(key, value)
        
        if RICH_AVAILABLE and self.console:
            if result['success']:
                self.console.print(f"[green]✓[/green] Set {key} = {value}")
            else:
                self.console.print(f"[red]✗[/red] Failed to set config: {result['error']}")
        else:
            if result['success']:
                print(f"✓ Set {key} = {value}")
            else:
                print(f"✗ Failed to set config: {result['error']}")
    
    def _reset_config(self):
        """Reset configuration to defaults"""
        if RICH_AVAILABLE and self.console:
            confirm = Confirm.ask("Reset all configuration to defaults?")
        else:
            confirm = input("Reset all configuration to defaults? (y/N): ").lower() == 'y'
        
        if confirm:
            result = self.cli.reset_config()
            if RICH_AVAILABLE and self.console:
                if result['success']:
                    self.console.print("[green]✓[/green] Configuration reset to defaults")
                else:
                    self.console.print(f"[red]✗[/red] Reset failed: {result['error']}")
            else:
                if result['success']:
                    print("✓ Configuration reset to defaults")
                else:
                    print(f"✗ Reset failed: {result['error']}")
    
    def _export_config(self, args: List[str]):
        """Export configuration to file"""
        # Implementation for config export
        pass
    
    def _import_config(self, args: List[str]):
        """Import configuration from file"""
        # Implementation for config import
        pass
    
    def _show_config_help(self):
        """Show help for config commands"""
        help_text = """
Config Commands:
  config show                   - Show current configuration
  config set <key> <value>      - Set configuration value
  config reset                  - Reset to default configuration
  config export <filename>      - Export configuration to file
  config import <filename>      - Import configuration from file

Examples:
  config show
  config set max_processes 16
  config export my_config.json
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Config Commands", border_style="blue"))
        else:
            print(help_text)
    
    def do_help(self, args: str):
        """Show help information"""
        if not args:
            self._show_general_help()
        else:
            command = args.strip()
            if hasattr(self, f'_show_{command}_help'):
                getattr(self, f'_show_{command}_help')()
            else:
                if RICH_AVAILABLE and self.console:
                    self.console.print(f"[red]No help available for '{command}'[/red]")
                else:
                    print(f"No help available for '{command}'")
    
    def _show_general_help(self):
        """Show general help information"""
        help_text = """
Available Commands:
  attack    - Attack management (start, stop, status, list)
  target    - Target analysis (analyze, resolve, profile, scan)
  monitor   - Monitoring and metrics (start, stop, dashboard, export)
  script    - Script execution (run, validate, create, list)
  config    - Configuration management (show, set, reset, export, import)
  help      - Show help information
  exit      - Exit interactive mode

Use 'help <command>' for detailed information about a specific command.
Use Tab for auto-completion of commands and options.
"""
        if RICH_AVAILABLE and self.console:
            self.console.print(Panel(help_text.strip(), title="Help", border_style="blue"))
        else:
            print(help_text)
    
    def do_exit(self, args: str):
        """Exit interactive mode"""
        if RICH_AVAILABLE and self.console:
            self.console.print("[yellow]Goodbye![/yellow]")
        else:
            print("Goodbye!")
        return True
    
    def do_quit(self, args: str):
        """Alias for exit"""
        return self.do_exit(args)
    
    def emptyline(self):
        """Handle empty line input"""
        pass
    
    def default(self, line: str):
        """Handle unknown commands"""
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[red]Unknown command:[/red] {line}")
            self.console.print("Type [bold]help[/bold] for available commands")
        else:
            print(f"Unknown command: {line}")
            print("Type 'help' for available commands")

class ScriptingEngine:
    """Engine for executing batch operations and scripts"""
    
    def __init__(self, cli_instance):
        self.cli = cli_instance
        self.script_dir = Path("scripts")
        self.script_dir.mkdir(exist_ok=True)
        
    def run_script(self, script_path: str) -> Dict[str, Any]:
        """Execute a script file"""
        try:
            script_file = Path(script_path)
            if not script_file.exists():
                script_file = self.script_dir / script_path
            
            if not script_file.exists():
                return {'success': False, 'error': f'Script file not found: {script_path}'}
            
            commands_executed = 0
            results = []
            
            with open(script_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        result = self._execute_command(line)
                        results.append({
                            'line': line_num,
                            'command': line,
                            'result': result
                        })
                        commands_executed += 1
                        
                        if not result.get('success', True):
                            logger.warning(f"Command failed at line {line_num}: {line}")
                            
                    except Exception as e:
                        logger.error(f"Error executing line {line_num}: {e}")
                        results.append({
                            'line': line_num,
                            'command': line,
                            'error': str(e)
                        })
            
            return {
                'success': True,
                'commands_executed': commands_executed,
                'results': results
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a single command"""
        # Parse and execute command through CLI
        # This would integrate with the main CLI command processing
        parts = shlex.split(command)
        if not parts:
            return {'success': True}
        
        cmd = parts[0]
        args = parts[1:]
        
        # Route to appropriate CLI method
        if cmd == 'attack':
            return self._handle_attack_command(args)
        elif cmd == 'target':
            return self._handle_target_command(args)
        elif cmd == 'config':
            return self._handle_config_command(args)
        else:
            return {'success': False, 'error': f'Unknown command: {cmd}'}
    
    def _handle_attack_command(self, args: List[str]) -> Dict[str, Any]:
        """Handle attack commands in scripts"""
        if not args:
            return {'success': False, 'error': 'Attack command requires subcommand'}
        
        subcommand = args[0]
        if subcommand == 'start':
            # Parse attack start parameters
            parser = argparse.ArgumentParser()
            parser.add_argument('--target', required=True)
            parser.add_argument('--port', type=int, required=True)
            parser.add_argument('--protocol', required=True)
            parser.add_argument('--duration', type=int, default=0)
            
            try:
                parsed_args = parser.parse_args(args[1:])
                return self.cli.start_attack(parsed_args)
            except SystemExit:
                return {'success': False, 'error': 'Invalid attack parameters'}
        
        return {'success': False, 'error': f'Unknown attack subcommand: {subcommand}'}
    
    def _handle_target_command(self, args: List[str]) -> Dict[str, Any]:
        """Handle target commands in scripts"""
        # Implementation for target commands
        return {'success': True}
    
    def _handle_config_command(self, args: List[str]) -> Dict[str, Any]:
        """Handle config commands in scripts"""
        # Implementation for config commands
        return {'success': True}
    
    def validate_script(self, script_path: str) -> Dict[str, Any]:
        """Validate script syntax without execution"""
        try:
            script_file = Path(script_path)
            if not script_file.exists():
                script_file = self.script_dir / script_path
            
            if not script_file.exists():
                return {'success': False, 'error': f'Script file not found: {script_path}'}
            
            errors = []
            warnings = []
            
            with open(script_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    # Basic syntax validation
                    try:
                        shlex.split(line)
                    except ValueError as e:
                        errors.append(f"Line {line_num}: Invalid syntax - {e}")
                        continue
                    
                    # Command validation
                    parts = shlex.split(line)
                    if parts:
                        cmd = parts[0]
                        if cmd not in ['attack', 'target', 'config', 'monitor']:
                            warnings.append(f"Line {line_num}: Unknown command '{cmd}'")
            
            return {
                'success': len(errors) == 0,
                'errors': errors,
                'warnings': warnings
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def list_scripts(self) -> List[Dict[str, Any]]:
        """List available scripts"""
        scripts = []
        
        for script_file in self.script_dir.glob("*.ddos"):
            try:
                stat = script_file.stat()
                
                # Count commands in script
                command_count = 0
                description = "No description"
                
                with open(script_file, 'r') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('# Description:'):
                        description = first_line[14:].strip()
                    
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            command_count += 1
                
                scripts.append({
                    'name': script_file.name,
                    'description': description,
                    'command_count': command_count,
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'size': stat.st_size
                })
                
            except Exception as e:
                logger.warning(f"Error reading script {script_file}: {e}")
        
        return sorted(scripts, key=lambda x: x['name'])

class AdvancedCLI:
    """Main CLI class that orchestrates all CLI functionality"""
    
    def __init__(self):
        self.config = CLIConfig()
        self.interactive_mode = None
        self.scripting_engine = None
        self.console = Console() if RICH_AVAILABLE else None
        
        # Initialize components
        self._init_components()
    
    def _init_components(self):
        """Initialize CLI components"""
        self.interactive_mode = InteractiveMode(self)
        self.scripting_engine = ScriptingEngine(self)
    
    def run_interactive(self):
        """Start interactive mode"""
        if self.interactive_mode:
            self.interactive_mode.cmdloop()
    
    def run_command(self, command: str) -> Dict[str, Any]:
        """Execute a single command"""
        return self.scripting_engine._execute_command(command)
    
    def run_script(self, script_path: str) -> Dict[str, Any]:
        """Execute a script file"""
        return self.scripting_engine.run_script(script_path)
    
    # Placeholder methods for CLI functionality
    # These would integrate with the actual framework components
    
    def start_attack(self, args) -> Dict[str, Any]:
        """Start an attack with given parameters"""
        # This would integrate with the actual attack engine
        return {
            'success': True,
            'session_id': f"attack_{int(time.time())}_{os.urandom(4).hex()}"
        }
    
    def stop_attack(self, session_id: str) -> Dict[str, Any]:
        """Stop an active attack"""
        return {'success': True}
    
    def get_attack_status(self) -> Dict[str, Any]:
        """Get status of active attacks"""
        return {'attacks': []}
    
    def list_all_attacks(self) -> List[Dict[str, Any]]:
        """List all attacks (active and historical)"""
        return []
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Analyze target for optimal attack parameters"""
        return {
            'success': True,
            'target': target,
            'ip': '192.168.1.1',
            'open_ports': [80, 443, 22],
            'services': ['HTTP', 'HTTPS', 'SSH'],
            'recommended_protocol': 'HTTP',
            'optimal_packet_size': 1460
        }
    
    def resolve_target(self, domain: str) -> Dict[str, Any]:
        """Resolve domain to IP address"""
        return {
            'success': True,
            'ip': '192.168.1.1'
        }
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics"""
        return {
            'Active Attacks': 0,
            'Total PPS': 0,
            'Total Bandwidth': '0 Mbps',
            'CPU Usage': '0%',
            'Memory Usage': '0%'
        }
    
    def export_metrics(self, format: str, output: str) -> Dict[str, Any]:
        """Export metrics to file"""
        filename = f"{output}.{format}"
        return {
            'success': True,
            'filename': filename
        }
    
    def list_scripts(self) -> List[Dict[str, Any]]:
        """List available scripts"""
        return self.scripting_engine.list_scripts()
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration"""
        return {
            'max_processes': 8,
            'default_timeout': 30,
            'auto_optimize': True,
            'log_level': 'INFO'
        }
    
    def set_config(self, key: str, value: str) -> Dict[str, Any]:
        """Set configuration value"""
        return {'success': True}
    
    def reset_config(self) -> Dict[str, Any]:
        """Reset configuration to defaults"""
        return {'success': True}

def main():
    """Main entry point for CLI"""
    cli = AdvancedCLI()
    
    if len(sys.argv) > 1:
        # Command-line mode
        command = ' '.join(sys.argv[1:])
        result = cli.run_command(command)
        
        if not result.get('success', True):
            print(f"Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    else:
        # Interactive mode
        cli.run_interactive()

if __name__ == "__main__":
    main()