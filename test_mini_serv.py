#!/usr/bin/env python3

import subprocess
import socket
import threading
import time
import os
import sys
import signal
from pathlib import Path

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

class MiniServTester:
    def __init__(self):
        self.exec_name = "mini_serv"
        self.src_name = "mini_serv.c"
        self.port = 4242
        self.server_process = None
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0

        self.parent_dir = Path(__file__).parent.parent
        self.src_path = self.parent_dir / self.src_name
        self.exec_path = self.parent_dir / self.exec_name

    def log(self, message, color=Colors.NC):
        print(f"{color}{message}{Colors.NC}")

    def kill_processes_on_port(self, port):
        try:
            result = subprocess.run(["lsof", "-ti", f":{port}"],
                                   capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                self.log(f"   Processes found on port {port}: {pids}", Colors.BLUE)

                for pid in pids:
                    if pid.strip():
                        try:
                            subprocess.run(["kill", "-9", pid.strip()],
                                         capture_output=True)
                            self.log(f"   Process {pid} killed", Colors.BLUE)
                        except:
                            pass

                time.sleep(0.5)

        except Exception as e:
            self.log(f"   Note: {e}", Colors.YELLOW)

    def test_result(self, success, description):
        self.total_tests += 1
        if success:
            self.log(f"✅ {description}", Colors.GREEN)
            self.passed_tests += 1
        else:
            self.log(f"❌ {description}", Colors.RED)
        self.test_results.append((success, description))

    def compile_program(self):
        self.log("[+] Compiling program...", Colors.YELLOW)

        if not self.src_path.exists():
            self.log(f"❌ File {self.src_name} not found in {self.parent_dir}", Colors.RED)
            return False

        original_cwd = os.getcwd()
        os.chdir(self.parent_dir)

        try:
            result = subprocess.run(
                ["clang", "-Wall", "-Wextra", "-Werror", self.src_name, "-o", self.exec_name],
                capture_output=True, text=True
            )

            if result.returncode != 0:
                self.log("❌ Compilation error:", Colors.RED)
                self.log(result.stderr)
                return False

            self.log("✅ Compilation successful", Colors.GREEN)
            return True

        finally:
            os.chdir(original_cwd)

    def check_forbidden_functions(self):
        self.log("[+] Checking allowed functions...", Colors.YELLOW)

        allowed_functions = [
            'write', 'close', 'select', 'socket', 'accept', 'listen',
            'send', 'recv', 'bind', 'strstr', 'malloc', 'realloc',
            'free', 'calloc', 'bzero', 'atoi', 'sprintf', 'strlen',
            'exit', 'strcpy', 'strcat', 'memset', 'memcpy'
        ]

        system_functions = [
            '__darwin_check_fd_set_overflow', '__memset_chk', '__sprintf_chk',
            'darwin_check_fd_set_overflow', 'memset_chk', 'sprintf_chk',
            '__chkstk_darwin', '__stack_chk_fail', '__stack_chk_guard',
            '__strcat_chk', '__strcpy_chk', 'chkstk_darwin', 'stack_chk_fail',
            'stack_chk_guard', 'strcat_chk', 'strcpy_chk'
        ]

        try:
            result = subprocess.run(["nm", "-u", str(self.exec_path)], capture_output=True, text=True)
            forbidden_found = []

            for line in result.stdout.split('\n'):
                if line.strip() and line.startswith('_'):
                    func_name = line.strip()[1:]
                    if (func_name not in allowed_functions and
                        func_name not in system_functions):
                        forbidden_found.append(func_name)

            if forbidden_found:
                self.test_result(False, "Only allowed functions used")
                self.log(f"Forbidden functions found: {', '.join(forbidden_found)}", Colors.RED)
            else:
                self.test_result(True, "Only allowed functions used")

        except Exception as e:
            self.log(f"Error during verification: {e}", Colors.RED)

    def test_argument_errors(self):
        self.log("[+] Test 1: Checking argument errors...", Colors.YELLOW)

        result = subprocess.run([str(self.exec_path)], capture_output=True, text=True)
        if "Wrong number of arguments" in result.stderr:
            self.test_result(True, "Error message for incorrect number of arguments")
        else:
            self.test_result(False, "Error message for incorrect number of arguments")
            self.log(f"stderr output: '{result.stderr.strip()}'", Colors.RED)

    def test_invalid_port(self):
        self.log("[+] Test 2: Testing problematic ports...", Colors.YELLOW)

        self.log("   Testing privileged port (80)...", Colors.BLUE)
        process1 = subprocess.Popen([str(self.exec_path), "80"],
                                   stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        time.sleep(1)

        port_privileged_error = False
        if process1.poll() is not None:
            stderr_output = process1.stderr.read().decode()
            if "Fatal error" in stderr_output:
                port_privileged_error = True
        else:
            process1.terminate()
            process1.wait()

        self.log("   Testing busy port...", Colors.BLUE)
        temp_socket = None
        port_busy_error = False

        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            temp_socket.bind(('127.0.0.1', 9999))
            temp_socket.listen(1)

            process2 = subprocess.Popen([str(self.exec_path), "9999"],
                                       stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            time.sleep(1)

            if process2.poll() is not None:
                stderr_output = process2.stderr.read().decode()
                if "Fatal error" in stderr_output:
                    port_busy_error = True
            else:
                process2.terminate()
                process2.wait()

        except Exception as e:
            self.log(f"   Error during busy port test: {e}", Colors.RED)
        finally:
            if temp_socket:
                temp_socket.close()

        self.log("   Testing out of range port (70000)...", Colors.BLUE)
        process3 = subprocess.Popen([str(self.exec_path), "70000"],
                                   stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        time.sleep(1)

        port_invalid_error = False
        if process3.poll() is not None:
            stderr_output = process3.stderr.read().decode()
            if "Fatal error" in stderr_output:
                port_invalid_error = True
        else:
            process3.terminate()
            process3.wait()

        if port_privileged_error or port_busy_error or port_invalid_error:
            self.test_result(True, "Error handling for problematic ports")
            self.log(f"   ✅ Privileged: {port_privileged_error}, Busy: {port_busy_error}, Invalid: {port_invalid_error}", Colors.GREEN)
        else:
            self.test_result(False, "Error handling for problematic ports")
            self.log("   ❌ No errors detected on problematic ports", Colors.RED)

    def start_server(self):
        self.log(f"[+] Test 3: Starting server on port {self.port}...", Colors.YELLOW)

        self.log(f"   Cleaning port {self.port}...", Colors.BLUE)
        self.kill_processes_on_port(self.port)

        try:
            self.server_process = subprocess.Popen(
                [str(self.exec_path), str(self.port)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(1)

            if self.server_process.poll() is None:
                self.test_result(True, "Server startup")
                return True
            else:
                stderr_output = self.server_process.stderr.read().decode()
                self.test_result(False, "Server startup")
                self.log(f"Server error: {stderr_output}", Colors.RED)
                return False

        except Exception as e:
            self.test_result(False, "Server startup")
            self.log(f"Exception: {e}", Colors.RED)
            return False

    def test_client_connections(self):
        self.log("[+] Test 4: Client connections...", Colors.YELLOW)

        clients = []
        client_messages = []

        def client_handler(client_id, messages_list):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('127.0.0.1', self.port))

                received = ""
                sock.settimeout(2.0)

                while True:
                    try:
                        data = sock.recv(1024).decode()
                        if not data:
                            break
                        received += data

                        while '\n' in received:
                            line, received = received.split('\n', 1)
                            if line.strip():
                                messages_list.append(line.strip())

                    except socket.timeout:
                        break
                    except:
                        break

                sock.close()

            except Exception as e:
                self.log(f"Client {client_id} error: {e}", Colors.RED)

        for i in range(3):
            messages = []
            client_messages.append(messages)
            client_thread = threading.Thread(target=client_handler, args=(i, messages))
            client_thread.daemon = True
            client_thread.start()
            clients.append(client_thread)
            time.sleep(0.5)

        time.sleep(2)
        arrival_messages_found = 0
        for messages in client_messages:
            for msg in messages:
                if "server: client" in msg and "just arrived" in msg:
                    arrival_messages_found += 1

        if arrival_messages_found >= 2:
            self.test_result(True, "Client arrival messages")
        else:
            self.test_result(False, "Client arrival messages")
            self.log(f"Arrival messages found: {arrival_messages_found}", Colors.RED)

        return clients, client_messages

    def test_message_broadcasting(self):
        self.log("[+] Test 5: Message broadcasting...", Colors.YELLOW)

        client_sockets = []
        client_outputs = []

        try:
            for i in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('127.0.0.1', self.port))
                sock.settimeout(5.0)
                client_sockets.append(sock)
                client_outputs.append("")
                time.sleep(0.3)

            self.log(f"   {len(client_sockets)} clients connected", Colors.BLUE)

            time.sleep(1)

            for i, sock in enumerate(client_sockets):
                try:
                    while True:
                        data = sock.recv(1024).decode()
                        if not data:
                            break
                        client_outputs[i] += data
                except socket.timeout:
                    pass
                except:
                    pass

            for i in range(len(client_outputs)):
                client_outputs[i] = ""

            test_message = "hello world test"
            self.log(f"   Client 0 sends: '{test_message}'", Colors.BLUE)
            client_sockets[0].send(f"{test_message}\n".encode())

            time.sleep(1.5)

            messages_received = []
            for i in range(1, len(client_sockets)):
                try:
                    data = client_sockets[i].recv(2048).decode()
                    client_outputs[i] += data
                    messages_received.append(client_outputs[i])
                    self.log(f"   Client {i} received: '{client_outputs[i].strip()}'", Colors.BLUE)
                except socket.timeout:
                    self.log(f"   Client {i}: timeout (no message received)", Colors.RED)
                    messages_received.append("")
                except Exception as e:
                    self.log(f"   Client {i}: error {e}", Colors.RED)
                    messages_received.append("")

            success = False
            pattern_found = False

            for i, received in enumerate(messages_received):
                import re
                if re.search(r'client \d+: ' + re.escape(test_message), received):
                    success = True
                    pattern_found = True
                    client_id_match = re.search(r'client (\d+):', received)
                    if client_id_match:
                        found_id = client_id_match.group(1)
                        self.log(f"   ✅ Client {i+1} correctly received message: 'client {found_id}: {test_message}'", Colors.GREEN)
                    break

            if success:
                self.test_result(True, "Message broadcasting between clients")
            else:
                self.test_result(False, "Message broadcasting between clients")
                self.log("   ❌ No client received message in expected format", Colors.RED)
                self.log(f"   Expected pattern: 'client [ID]: {test_message}'", Colors.YELLOW)
                for i, received in enumerate(messages_received):
                    if received.strip():
                        self.log(f"   Client {i+1} received: '{received.strip()}'", Colors.YELLOW)

        except Exception as e:
            self.test_result(False, "Message broadcasting between clients")
            self.log(f"Error during test: {e}", Colors.RED)

        finally:
            for sock in client_sockets:
                try:
                    sock.close()
                except:
                    pass

    def test_multiline_messages(self):
        self.log("[+] Test 6: Multi-line messages...", Colors.YELLOW)

        try:
            client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            client1.connect(('127.0.0.1', self.port))
            client2.connect(('127.0.0.1', self.port))

            client2.settimeout(3.0)

            time.sleep(0.5)

            client1.send(b"line1\nline2\nline3\n")
            time.sleep(1)

            received_data = ""
            try:
                while True:
                    data = client2.recv(1024).decode()
                    if not data:
                        break
                    received_data += data
                    if received_data.count('\n') >= 3:
                        break
            except socket.timeout:
                pass

            lines_found = 0
            import re

            for line_num in [1, 2, 3]:
                pattern = r'client \d+: line' + str(line_num)
                if re.search(pattern, received_data):
                    lines_found += 1

            if lines_found >= 2:
                self.test_result(True, "Multi-line message handling")
                self.log(f"   ✅ {lines_found}/3 multi-lines correctly formatted", Colors.GREEN)
            else:
                self.test_result(False, "Multi-line message handling")
                self.log(f"Lines found: {lines_found}/3", Colors.RED)
                self.log(f"Data received: '{received_data.strip()}'", Colors.YELLOW)

            client1.close()
            client2.close()

        except Exception as e:
            self.test_result(False, "Multi-line message handling")
            self.log(f"Error: {e}", Colors.RED)

    def test_client_disconnection(self):
        self.log("[+] Test 7: Client disconnection...", Colors.YELLOW)

        try:
            client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            client1.connect(('127.0.0.1', self.port))
            client2.connect(('127.0.0.1', self.port))

            client2.settimeout(3.0)
            time.sleep(0.5)

            client1.close()
            time.sleep(1)

            received_data = ""
            try:
                while True:
                    data = client2.recv(1024).decode()
                    if not data:
                        break
                    received_data += data
                    if "just left" in received_data:
                        break
            except socket.timeout:
                pass

            if "server: client" in received_data and "just left" in received_data:
                self.test_result(True, "Client disconnection message")
            else:
                self.test_result(False, "Client disconnection message")
                self.log(f"Data received: '{received_data.strip()}'", Colors.RED)

            client2.close()

        except Exception as e:
            self.test_result(False, "Client disconnection message")
            self.log(f"Error: {e}", Colors.RED)

    def test_performance(self):
        self.log("[+] Test 8: Performance test...", Colors.YELLOW)

        try:
            client1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            client1.connect(('127.0.0.1', self.port))
            client2.connect(('127.0.0.1', self.port))

            client2.settimeout(3.0)
            time.sleep(0.5)

            for i in range(5):
                client1.send(f"rapid message {i+1}\n".encode())

            time.sleep(1)

            received_data = ""
            try:
                while True:
                    data = client2.recv(1024).decode()
                    if not data:
                        break
                    received_data += data
            except socket.timeout:
                pass

            message_count = received_data.count("rapid message")

            if message_count >= 3:
                self.test_result(True, f"Rapid message handling ({message_count}/5 received)")
            else:
                self.test_result(False, f"Rapid message handling ({message_count}/5 received)")

            client1.close()
            client2.close()

        except Exception as e:
            self.test_result(False, "Rapid message handling")
            self.log(f"Error: {e}", Colors.RED)

    def check_code_requirements(self):
        self.log("[+] Checking code requirements...", Colors.YELLOW)

        with open(str(self.src_path), 'r') as f:
            code_content = f.read()

        if '#define' in code_content:
            self.test_result(False, "No #define in code")
        else:
            self.test_result(True, "No #define in code")

        if '127.0.0.1' in code_content or '2130706433' in code_content:
            self.test_result(True, "Listen on 127.0.0.1 only")
        else:
            self.test_result(False, "Listen on 127.0.0.1 only")

    def cleanup(self):
        if self.server_process and self.server_process.poll() is None:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()

        if self.exec_path.exists():
            self.exec_path.unlink()

    def generate_report(self):
        self.log("\n" + "="*50, Colors.YELLOW)
        self.log("CONFORMITY REPORT", Colors.YELLOW)
        self.log("="*50, Colors.YELLOW)

        self.log(f"\nTests passed: {Colors.GREEN}{self.passed_tests}{Colors.NC}/{self.total_tests}")

        if self.passed_tests == self.total_tests:
            self.log("\n🎉 All tests passed successfully!", Colors.GREEN)
            self.log("Your code meets all requirements.", Colors.GREEN)
        else:
            self.log(f"\n⚠️  {self.total_tests - self.passed_tests} test(s) failed", Colors.RED)

            self.log("\n📋 RECOMMENDATIONS FOR SUCCESS:", Colors.YELLOW)

            failed_tests = [desc for success, desc in self.test_results if not success]
            for test in failed_tests:
                self.log(f"- {test}", Colors.RED)

            self.log("\n📖 KEY REQUIREMENTS TO CHECK:", Colors.BLUE)
            self.log("1. Exact error message: 'Wrong number of arguments'", Colors.BLUE)
            self.log("2. 'Fatal error' messages for system errors", Colors.BLUE)
            self.log("3. Messages 'server: client X just arrived\\n'", Colors.BLUE)
            self.log("4. Messages 'server: client X just left\\n'", Colors.BLUE)
            self.log("5. Format: 'client X: ' before each message line", Colors.BLUE)
            self.log("6. Multi-line message handling", Colors.BLUE)
            self.log("7. Broadcast to all clients EXCEPT sender", Colors.BLUE)
            self.log("8. No #define in code", Colors.BLUE)
            self.log("9. Listen on 127.0.0.1 only", Colors.BLUE)
            self.log("10. Non-blocking handling with select()", Colors.BLUE)

    def generate_test_report_file(self):
        report_filename = "test_rapport.txt"

        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("DETAILED TEST REPORT - MINI_SERV\n")
                f.write("="*60 + "\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"File tested: {self.src_name}\n")
                f.write(f"Port used: {self.port}\n")
                f.write("\n")

                f.write("GLOBAL SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Tests passed: {self.passed_tests}/{self.total_tests}\n")
                f.write(f"Success rate: {(self.passed_tests/self.total_tests)*100:.1f}%\n")
                f.write("\n")

                f.write("TEST DETAILS\n")
                f.write("-" * 20 + "\n")
                for i, (success, description) in enumerate(self.test_results, 1):
                    status = "✅ PASSED" if success else "❌ FAILED"
                    f.write(f"{i:2d}. {status:10} - {description}\n")
                f.write("\n")

                failed_tests = [desc for success, desc in self.test_results if not success]
                if failed_tests:
                    f.write("FAILED TESTS - ACTIONS REQUIRED\n")
                    f.write("-" * 35 + "\n")
                    for i, test in enumerate(failed_tests, 1):
                        f.write(f"{i}. {test}\n")
                    f.write("\n")

                f.write("CONCLUSION\n")
                f.write("-" * 15 + "\n")
                if self.passed_tests == self.total_tests:
                    f.write("🎉 EXCELLENT! Your code meets all requirements.\n")
                    f.write("Your mini_serv is ready for evaluation.\n")
                elif self.passed_tests >= self.total_tests * 0.8:
                    f.write("✅ GOOD WORK! Your code is almost compliant.\n")
                    f.write("A few minor corrections are sufficient.\n")
                elif self.passed_tests >= self.total_tests * 0.6:
                    f.write("⚠️  ACCEPTABLE WORK. Several corrections needed.\n")
                    f.write("Focus on the critical issues listed above.\n")
                else:
                    f.write("❌ INSUFFICIENT WORK. Major revision required.\n")
                    f.write("Carefully review the subject and recommendations.\n")

                f.write("\n")
                f.write("="*60 + "\n")
                f.write("End of report - Generated by test_mini_serv.py\n")
                f.write("="*60 + "\n")

            self.log(f"\n📄 Detailed report saved in: {report_filename}", Colors.BLUE)

        except Exception as e:
            self.log(f"Error creating report: {e}", Colors.RED)

    def run_all_tests(self):
        try:
            if not self.compile_program():
                return

            self.check_forbidden_functions()
            self.check_code_requirements()
            self.test_argument_errors()
            self.test_invalid_port()

            if self.start_server():
                self.test_client_connections()
                self.test_message_broadcasting()
                self.test_multiline_messages()
                self.test_client_disconnection()
                self.test_performance()
            else:
                self.log("❌ Unable to start server, client tests skipped", Colors.RED)

        finally:
            self.cleanup()
            self.generate_report()
            self.generate_test_report_file()

def main():
    tester = MiniServTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main()
