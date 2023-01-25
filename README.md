# caddy-c2
Caddy v2 module to filter requests based on C2 profiles.

## Installation

You can build Caddy by yourself by [installing xcaddy](https://github.com/caddyserver/xcaddy) and running:
```
xcaddy build --with github.com/lum8rjack/caddy-c2
```

## Usage

You can use this module as a matcher to allow only traffic based on the C2 profile. This modules currently works with the following C2 profiles:
- Cobalt Strike

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

## References

- [SeeProxy](https://github.com/nopbrick/SeeProxy) - Go reverse proxy with Cobalt Strike malleable profile validation. This project gave me the idea to create this caddy module.

