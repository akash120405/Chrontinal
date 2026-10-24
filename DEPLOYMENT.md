# GitHub source and live website deployment

This repository contains a Next.js dashboard plus ClickHouse, Redpanda, MinIO,
AI agents, and other services. A GitHub repository can hold the source. GitHub
Pages serves static files only, so it cannot run the dashboard's sign-in, Groq
API route, live data APIs, or the backend services. Run the full stack on a VM
and point a domain at that VM for the live website URL.

## 1. Publish the source to GitHub

Create an empty repository in your GitHub account. From this directory, run:

```sh
git init
git add .
git status --short
git commit -m "Prepare CLIF website for deployment"
git branch -M main
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

Replace `OWNER/REPOSITORY` with your repository path. Before committing,
check that `.env`, `dashboard/.env.local`, and
`k8s/base/secrets/credentials.env` are absent from `git status`. The old
fixed Kubernetes passwords were removed from the source. If those passwords
were ever used, rotate them. Keep the repository private if log samples or
other project data are sensitive.

## 2. Provision and configure the VM

The supplied full Compose file targets a Linux VM with about 28 vCPU, 40 GB
RAM, and at least 200 GB SSD. Install Docker Engine and its Compose plugin.
Clone the GitHub repository on the VM, then create a local environment file:

```sh
git clone https://github.com/OWNER/REPOSITORY.git /opt/clif
cd /opt/clif
cp .env.example .env
chmod 600 .env
```

Edit `.env` on the VM. Set the actual VM public IP in `GCP_EXTERNAL_IP` and
fill every empty secret, including `GROQ_API_KEY`. The supplied Groq key belongs
only in this VM file or a cloud secret manager, never in Git or a
`NEXT_PUBLIC_` variable. Set a unique dashboard username and a password of
at least 12 characters. Generate `CLIF_AUTH_SECRET` and `CLIF_HMAC_KEY` with
`openssl rand -hex 32`. The auth secret must contain at least 32 bytes.
Use unique ClickHouse, MinIO, Grafana, and Flask secrets too. Set
`CLIF_HTTPS=true` when using the HTTPS reverse proxy described below. For
temporary localhost-only HTTP testing, set it to `false`.

Check the resolved configuration and start the stack:

```sh
docker compose --env-file .env -f docker-compose.gcp-full.yml config --quiet
docker compose --env-file .env -f docker-compose.gcp-full.yml up -d --build
docker compose --env-file .env -f docker-compose.gcp-full.yml ps
curl -fsS http://127.0.0.1:3001/api/health
```

The public landing page is `/`; the dashboard sign-in is `/login`. The
dashboard listens on VM loopback port 3001. Its AI route calls Groq from the
server using the configured key. Other data, admin, monitoring, and demo
ports also bind to `CLIF_PRIVATE_BIND_IP`, which defaults to `127.0.0.1`.
Vector's log ingestion ports bind to `VECTOR_INGEST_BIND_IP`, which defaults
to `0.0.0.0`; set it to a private interface if ingress should stay private.

## 3. Attach a domain and HTTPS

Create a DNS `A` record such as `soc.example.com` pointing to the VM public
IP. Put a trusted TLS reverse proxy in front of port 3001. For example, a
Caddyfile on the VM can contain:

```text
soc.example.com {
    reverse_proxy 127.0.0.1:3001
}
```

Install and run Caddy using its official documentation, substituting your
domain. Its automatic certificate flow needs inbound TCP ports 80 and 443.
After DNS and TLS are ready, verify:

```sh
curl -fsS https://soc.example.com/api/health
```

The resulting `https://soc.example.com/` is the website link to attach to
the GitHub repository description.

## 4. Restrict inbound network access

In the cloud provider's firewall, allow 80/443 from the Internet and SSH only
from your administrator IP. Block public access to dashboard port 3001,
Grafana 3002, ClickHouse 8123/9000, MinIO 9002/9003, Redpanda
19092/29092/39092 and admin ports, Prometheus 9090, the SecureBank demo on
5000, and other Compose ports. Open Vector ingestion ports 1514 TCP/UDP,
8687 TCP, 9514 TCP, and 8125 UDP only to trusted senders if remote logs are
needed. The cloud firewall remains important even though most ports bind to
loopback. Keep backend traffic on the Compose network.

## Kubernetes alternative

Kubernetes deployment uses `k8s/base/secrets/credentials.env`, which is
ignored by Git. Copy it from `credentials.env.example`, replace every
placeholder, and keep it on the deployment machine. Kustomize generates the
`clif-credentials` Secret from the file. See [k8s/README.md](k8s/README.md).
