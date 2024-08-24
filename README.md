# caddy-c2

![Tests](https://github.com/lum8rjack/caddy-c2/actions/workflows/go.yml/badge.svg)

Caddy v2 module to match network traffic and only allow traffic based on C2 profiles. This module currently works with the following C2 frameworks:
- [Cobalt Strike](https://www.cobaltstrike.com/)
- [Empire](https://github.com/BC-SECURITY/Empire) - Uses the same profile as Cobalt Strike ([docs](https://bc-security.gitbook.io/empire-wiki/listeners/malleable-c2))
- [NimPlant](https://github.com/chvancooten/NimPlant)

## Installation

You can build Caddy by yourself by installing [xcaddy](https://github.com/caddyserver/xcaddy) and running:
```bash
xcaddy build --with github.com/lum8rjack/caddy-c2
```

If you want to clone and make any changes, you can test locally with the following command:
```bash
# Specify the location of the local build
 xcaddy build --with github.com/lum8rjack/caddy-c2=./caddy-c2
```

### Caddyfile

Allow access to the C2 server for only requests that match the profile. Everything else is redirected to a different website. The supported frameworks include:
- cobaltstrike
- empire
- nimplant

Below is an example Caddyfile for use with Cobalt Strike.
```
{
  admin off
  debug
}

https://test.example.com {
  @c2 {
    c2_profile {
      profile "/usr/share/cobaltstrike/cobaltstrike.profile"
      framework "cobaltstrike"
    }
  }

  handle @c2 {
    reverse_proxy https://localhost:8080 {
      header_up Host {http.request.host}
      transport http {
        tls
        tls_insecure_skip_verify
      }
    }
  }

  handle /* {
    redir https://example.com{uri}
  }
}
```


## Future Improvements

- Auto reload when the C2 profile change
- Support additional C2 frameworks
  - [Havoc](https://github.com/HavocFramework/Havoc)
  - [Mythic](https://github.com/its-a-feature/Mythic)
  - [Sliver](https://github.com/BishopFox/sliver)

## References

- [SeeProxy](https://github.com/nopbrick/SeeProxy) - Go reverse proxy with Cobalt Strike malleable profile validation. This project gave me the idea to create this caddy module.
- [goMalleable](https://github.com/D00Movenok/goMalleable) - Cobalt Strike malleable C2 profile parser
- [Malleable-C2-Profiles](https://github.com/xx0hcd/Malleable-C2-Profiles) - Cobalt Strike template used for testing.

