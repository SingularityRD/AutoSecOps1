{{/* Caddyfile mirroring the root Caddyfile used by Docker Compose. */}}
{{- define "autosecops.caddyfile" -}}
{{- $api := include "autosecops.internalApiUrl" . }}
{{- $mcp := printf "http://%s:8099" (include "autosecops.componentFullname" (dict "root" . "component" "mcp")) }}
{{- $ui := printf "http://%s:3000" (include "autosecops.componentFullname" (dict "root" . "component" "ui")) }}
{{- $s3 := include "autosecops.blobProxyUpstream" . }}
{
	# TLS terminates at the Ingress or load balancer in front of Caddy.
	auto_https off
	admin off
	servers {
		trusted_proxies static {{ join " " .Values.caddy.trustedProxyCidrs }}
		trusted_proxies_strict
	}
}

:8080 {
{{- if $s3 }}
	# Presigned URLs are signed against the internal blob endpoint, so
	# forward that host upstream or SigV4 signatures fail.
	handle_path /s3/* {
		reverse_proxy {{ $s3 }} {
			header_up Host {upstream_hostport}
			header_up -Server
		}
	}
{{- end }}

	handle_path /api* {
		reverse_proxy {{ $api }} {
			header_up X-Forwarded-For {client_ip}
			header_up X-Real-IP {client_ip}
			header_up X-Forwarded-Host {host}
			header_up X-Forwarded-Proto {scheme}
		}
	}
{{- if .Values.mcp.enabled }}

	handle /mcp* {
		reverse_proxy {{ $mcp }} {
			flush_interval -1
			header_up X-Forwarded-For {client_ip}
			header_up X-Real-IP {client_ip}
		}
	}

	@mcp_oauth_routes {
		path /.well-known/oauth-authorization-server
		path /.well-known/oauth-protected-resource /.well-known/oauth-protected-resource/*
		path /authorize /authorize/*
		path /token
		path /register
		path /consent /consent/*
		path /auth/callback /auth/callback/*
	}
	handle @mcp_oauth_routes {
		reverse_proxy {{ $mcp }} {
			flush_interval -1
			header_up X-Forwarded-For {client_ip}
			header_up X-Real-IP {client_ip}
		}
	}
{{- end }}

	reverse_proxy {{ $ui }} {
		header_up X-Forwarded-For {client_ip}
		header_up X-Real-IP {client_ip}
	}
}
{{- end }}
