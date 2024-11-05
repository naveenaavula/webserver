# Import required standard Python libraries
import time  # For adding delays and timing operations
import argparse  # For parsing command line arguments
import mimetypes  # For determining file content types
import os  # For file and path operations
import threading  # For handling multiple client connections
import socket  # For network operations
from urllib.parse import unquote  # For decoding URL-encoded characters
from datetime import datetime  # For generating timestamps


def detect_content_type(file_location):
    """
    Determine the file extension from a given file path
    Args:
        file_location: Path to the file
    Returns:
        The lowercase file extension including the dot
    """
    # Split the file path into name and extension
    _, extension = os.path.splitext(file_location)
    # Return the lowercase version of the extension
    return extension.lower()


class WebServer:
    # Define constant values for file paths
    ROOT_PAGE = "index.html"  # Default page to serve
    ERROR_400 = "error/400.html"  # Bad request error page
    ERROR_403 = "error/403.html"  # Forbidden error page
    ERROR_404 = "error/404.html"  # Not found error page
    ERROR_501 = "error/501.html"  # Not implemented error page

    # Set to store all active client connections
    active_connections = set()

    def __init__(self, connection, document_root, http_version, verbose=False, connection_timeout=10):
        """
        Initialize the WebServer instance
        Args:
            connection: Socket connection object
            document_root: Root directory for serving files
            http_version: HTTP protocol version
            verbose: Enable detailed logging
            connection_timeout: Socket timeout in seconds
        """
        # Store the client connection socket
        self.connection = connection
        # Store the web root directory path
        self.document_root = document_root
        # Store the HTTP version being used
        self.http_version = http_version
        # Store the connection timeout value
        self.connection_timeout = connection_timeout
        # Store the verbose logging flag
        self.verbose = verbose

        # If there's an active connection, track it
        if connection:
            # Get the client's IP address
            remote_addr = connection.getpeername()[0]
            # If this is a new client, add them to our set
            if remote_addr not in self.active_connections:
                self.active_connections.add(remote_addr)
                print(f"New connection established: {remote_addr}")

    def initialize(self, port_number, server_timeout=500):
        """
        Start the web server and begin accepting connections
        Args:
            port_number: Port to listen on
            server_timeout: Server socket timeout in seconds
        """
        try:
            # Create a new TCP socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                # Set the server socket timeout
                server_socket.settimeout(server_timeout)
                # Bind the socket to localhost on the specified port
                server_socket.bind(('localhost', port_number))
                # Start listening for connections (queue up to 3)
                server_socket.listen(3)
                print(f"Web server initialized.\nPort: {port_number}\n")
                thread_counter = 0

                # Main server loop
                while True:
                    # Increment thread counter for unique thread naming
                    thread_counter += 1
                    # Accept incoming connection
                    client_conn, client_addr = server_socket.accept()
                    # Create new server instance for this connection
                    server_instance = WebServer(client_conn, self.document_root, 
                                             self.http_version, self.verbose)
                    # Create and start new thread for handling this request
                    server_thread = threading.Thread(
                        target=server_instance.handle_request,
                        name=f"RequestHandler-{thread_counter}"
                    )
                    server_thread.start()

        except Exception as error:
            print(f"Connection timeout: {error}")
        finally:
            # Ensure server socket is closed
            server_socket.close()

    def handle_request(self):
        """Handle an incoming HTTP request"""
        try:
            # Use context managers to handle socket streams
            with self.connection, \
                 self.connection.makefile('r', buffering=1) as request_stream, \
                 self.connection.makefile('wb', buffering=0) as response_stream:

                # Read the first line of the HTTP request
                request_line = request_stream.readline()
                # Split into components (method, path, version)
                request_components = request_line.split(' ')
                
                # Check for malformed request
                if len(request_components) < 2:
                    print("Malformed request received")
                    self.handle_bad_request(response_stream, request_line)
                    return

                # Extract method and path from request
                request_method, resource_path = request_components[0], unquote(request_components[1])

                # Log request details if verbose mode is enabled
                if self.verbose:
                    print("Requested resource:", resource_path)
                
                # Validate request method and resource type
                if (request_method.upper() != "GET") or (not self.is_resource_supported(resource_path)):
                    self.handle_bad_request(response_stream, request_method)
                    return

                # Resolve the actual file path
                actual_path = self.resolve_resource_path(resource_path)
                if actual_path is None:
                    self.handle_not_found(response_stream, resource_path)
                    return

                # Check read permissions
                if not os.access(actual_path, os.R_OK):
                    self.handle_forbidden(response_stream, resource_path)
                    return

                # Construct HTTP version string
                server_protocol = "HTTP/" + self.http_version
                
                # Log request handling details if verbose
                if self.verbose:
                    print(f"Thread: {threading.current_thread().name}, "
                          f"Serving: {actual_path}")
                
                # Serve the requested resource
                self.deliver_resource(response_stream, actual_path, 
                                   http_version=server_protocol)

                # Handle HTTP/1.0 connection closure
                if server_protocol == "HTTP/1.0":
                    time.sleep(2)
                    print("HTTP/1.0 connection terminated")

        except Exception as error:
            print(f"Request handling error: {error}")
        finally:
            # Clean up the connection
            self.cleanup_connection()

    def is_resource_supported(self, resource_path):
        """
        Check if the requested resource type is supported
        Args:
            resource_path: Path to the requested resource
        Returns:
            Boolean indicating if the resource type is supported
        """
        # Split path into name and extension
        _, extension = os.path.splitext(resource_path)
        file_extension = extension.lower()
        # Define set of allowed file types
        allowed_types = {'.pdf', '.jpeg', '.jpg', '.png', '.txt', 
                        '.gif', '.html', '.mp4', '.json', '', '.js', '.css'}
        return file_extension in allowed_types

    def resolve_resource_path(self, resource_name):
        """
        Convert URL path to actual file system path
        Args:
            resource_name: The requested resource path
        Returns:
            Full path to the resource or None if not found
        """
        # Handle root path request
        if resource_name == '/':
            resource_name = self.ROOT_PAGE
        else:
            # Remove leading slash
            resource_name = resource_name[1:]

        # Create full path and normalize it
        full_path = os.path.normpath(os.path.join(self.document_root, resource_name))

        # Return path if file exists, None otherwise
        return full_path if os.path.exists(full_path) else None

    def deliver_resource(self, response_stream, resource_path, 
                        status="200 OK", http_version="HTTP/1.1"):
        """
        Send the requested resource to the client
        Args:
            response_stream: Stream for sending response
            resource_path: Path to the resource to send
            status: HTTP status code and message
            http_version: HTTP version string
        """
        try:
            # Open the resource file in binary mode
            with open(resource_path, 'rb') as resource_file:
                # Determine the content type
                content_type, _ = mimetypes.guess_type(resource_path)

                # Construct HTTP headers
                headers = [
                    f"{http_version} {status}",
                    "Server: Python Custom WebServer",
                    f"Date: {self.generate_timestamp()}",
                    f"Content-type: {content_type}",
                    f"Content-length: {os.path.getsize(resource_path)}",
                    "",
                    ""
                ]
                # Write headers to response stream
                response_stream.write("\r\n".join(headers).encode('utf-8'))

                # Set timeout for HTTP/1.0 connections
                if http_version == "HTTP/1.0":
                    self.connection.settimeout(self.connection_timeout)

                # Read and send file in chunks
                while chunk := resource_file.read(4096):
                    response_stream.write(chunk)

        except Exception as error:
            print(f"Resource delivery error: {error}")
        finally:
            resource_file.close()

    def handle_bad_request(self, response_stream, request_info):
        """Handle HTTP 400 Bad Request errors"""
        print(f"400 Bad Request: {request_info}")
        self.deliver_resource(response_stream, self.ERROR_400, "400 Bad Request")

    def handle_not_found(self, response_stream, resource_name):
        """Handle HTTP 404 Not Found errors"""
        print(f"404 Not Found: {resource_name}")
        self.deliver_resource(response_stream, self.ERROR_404, "404 Not Found")

    def handle_forbidden(self, response_stream, resource_name):
        """Handle HTTP 403 Forbidden errors"""
        print(f"403 Forbidden: {resource_name}")
        self.deliver_resource(response_stream, self.ERROR_403, "403 Forbidden")

    def handle_unsupported_method(self, response_stream, method):
        """Handle HTTP 501 Not Implemented errors"""
        print(f"501 Not Implemented: {method}")
        self.deliver_resource(response_stream, self.ERROR_501, "501 Not Implemented")

    def generate_timestamp(self):
        """Generate RFC-compliant timestamp for HTTP headers"""
        return datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    def cleanup_connection(self):
        """Clean up client connection and update active connections set"""
        try:
            if self.connection:
                # Get client address
                remote_addr = self.connection.getpeername()[0]
                # Close the connection
                self.connection.close()

                # Remove from active connections
                if remote_addr in self.active_connections:
                    self.active_connections.remove(remote_addr)
                    print(f"Connection terminated: {remote_addr}")
        except OSError as error:
            # Ignore "Bad file descriptor" errors
            if error.errno != 9:
                print(f"Connection cleanup error: {error}")


# Main entry point
if __name__ == "__main__":
    try:
        # Set up command line argument parser
        arg_parser = argparse.ArgumentParser(description="HTTP Server Implementation")
        arg_parser.add_argument("-document_root", required=True, 
                              help="Root directory for web content")
        arg_parser.add_argument("-port", type=int, required=True, 
                              help="Server port (8000-9999)")
        arg_parser.add_argument("--http_version", type=str, default="1.1",
                              help="HTTP Version (1.0 or 1.1)")
        arg_parser.add_argument("--verbose", type=bool, default=False,
                              help="Enable verbose logging")
        args = arg_parser.parse_args()

        # Extract command line arguments
        document_root = args.document_root
        port = args.port
        http_version = args.http_version
        verbose = args.verbose

        # Validate port number
        if not (8000 <= port <= 9999):
            raise ValueError("Port must be between 8000 and 9999")

        # Validate web root directory exists
        if not os.path.exists(document_root):
            raise FileNotFoundError(f"Web root directory not found: {document_root}")

        # Validate HTTP version
        if http_version not in {'1.1', '1.0'}:
            raise ValueError("Supported HTTP versions: 1.0 or 1.1")
        
        # Create and start server
        server = WebServer(None, document_root, http_version, verbose)
        server.initialize(port)

    except Exception as error:
        print(f"Startup error: {error}")