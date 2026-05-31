# Honeypot Subdomain Website

Honeypot Subdomain Website is a Node.js project built to detect and slow down suspicious bot traffic on unused or decoy subdomains. The project listens for incoming requests, logs request information, tracks repeated activity by IP address, and responds differently when suspicious paths are requested.

This project was created to better understand web security, bot behavior, request logging, rate-based detection, and how Cloudflare Tunnel can be used to expose a local service through a subdomain.

## Purpose

The purpose of this project is to create a simple honeypot that can catch automated requests to common suspicious paths such as admin pages, WordPress login routes, XML-RPC endpoints, `.git` paths, and other routes that bots often scan for.

Instead of only returning a normal 404 response, the honeypot tracks request patterns and can slow down or block suspicious clients.

## Features

* Detects suspicious paths commonly requested by bots
* Tracks request counts per IP address
* Logs request information in structured JSON format
* Extracts client IP information from Cloudflare headers when available
* Soft-flags IP addresses that hit suspicious paths repeatedly
* Adds a delay for flagged clients to slow down repeated requests
* Hard-blocks IP addresses that exceed the request threshold
* Includes a local-only status endpoint for checking IP state
* Supports deployment behind Cloudflare Tunnel

## Tech Stack

* Node.js
* Express.js
* JavaScript
* Cloudflare Tunnel
* Linux systemd service setup

## Project Structure

```text
honeypot/
├── honey/
│   ├── honeypot.js
│   ├── package.json
│   ├── package-lock.json
│   ├── pi_linux_service_instructions.txt
│   ├── windows_manual_instructions.txt
│   └── windows_service_instruction.txt
├── LICENSE
└── README.md
```

## How It Works

The honeypot runs an Express server and monitors incoming requests. For each request, it records information such as the IP address, request path, method, status code, user agent, referrer, Cloudflare Ray ID, and country header when available.

When a client requests suspicious paths multiple times or sends too many requests in a short time window, the honeypot can mark the IP as suspicious. Flagged clients may receive delayed responses, while clients that exceed the hard-block threshold receive a forbidden response.

## Example Suspicious Paths

```text
/wp-login.php
/xmlrpc.php
/phpmyadmin
/admin
/cgi-bin
/.git
/server-status
```

## How to Run Locally

1. Clone the repository:

```bash
git clone https://github.com/Unknown903-dev/honeypot.git
```

2. Move into the project folder:

```bash
cd honeypot/honey
```

3. Install dependencies:

```bash
npm install
```

4. Run the honeypot:

```bash
node honeypot.js
```

5. Visit the local server:

```text
http://localhost:9000
```

## Cloudflare Tunnel Usage

This project can be used with Cloudflare Tunnel to route a subdomain to the local honeypot service. The included Linux setup instructions show how to create a tunnel, route DNS to the tunnel, and run the honeypot as a systemd service.

## What I Learned

While building this project, I practiced working with Express middleware, request logging, IP tracking, rate-based detection, Cloudflare headers, and basic defensive security concepts. I also learned how a honeypot can be used to observe suspicious web traffic and respond differently based on request behavior.

## Future Improvements

* Move policy settings into a config file
* Add persistent storage for blocked IPs
* Add better log rotation support
* Add tests for suspicious path detection
* Add a script command for starting the server
* Improve the admin/status endpoint
* Add documentation for safe deployment
* Remove unnecessary committed files such as `node_modules`

## Disclaimer

This project is for educational and defensive security purposes only. It should be used only on systems and domains that you own or have permission to monitor.

## Author

Created by Alex
GitHub: https://github.com/Unknown903-dev
