# caddy-c2
Caddy v2 module to filter requests based on C2 profiles.

## Installation

This caddy module uses the following Go packages:
```
# Cobalt Strike parser
github.com/D00Movenok/goMalleable
```

You can build Caddy by yourself by [installing xcaddy](https://github.com/caddyserver/xcaddy) and running:
```
xcaddy build --with github.com/lum8rjack/caddy-c2
```

## Usage

You can use this module as a matcher to allow only traffic based on the C2 profile. This modules currently works with the following C2 profiles:
- [Cobalt Strike](https://www.cobaltstrike.com/)

### Caddyfile

1. Allow access to Cobalt Strike only requests that match the profile:
```
test.example.org {
  @c2 {
    c2_profile {
      profile "/usr/share/cobaltstrike/cobaltstrike.profile"
      framework "cobaltstrike"
    }
  }

  handle @c2 {
    reverse_proxy localhost:8080
  }
}
```

## Future Improvements

- Add additional logging
- Support additional C2 frameworks
  - [Havoc](https://github.com/HavocFramework/Havoc)
  - [Mythic](https://github.com/its-a-feature/Mythic)
  - [Sliver](https://github.com/BishopFox/sliver)

## References

- [SeeProxy](https://github.com/nopbrick/SeeProxy) - Go reverse proxy with Cobalt Strike malleable profile validation. This project gave me the idea to create this caddy module.
- [Malleable-C2-Profiles](https://github.com/xx0hcd/Malleable-C2-Profiles) - Cobalt Strike template used for testing.

