---
name: New data source
about: Propose a public endpoint for the probe registry
title: ""
labels: enhancement
assignees: ""
---

**🔌 Endpoint**

```
GET https://...
```

**🧪 Verified responses**

<!-- run both from your machine; paste status codes and a trimmed body -->

Real handle (`torvalds` or similar):

```
HTTP/...
```

Non-existent handle (`zqxjwvunotfound991`):

```
HTTP/...
```

**🧭 Why the discriminator is reliable**

<!-- e.g. 200 + payload vs 404; or soft-404 distinguished by body regex -->

**✅ Scope check**

- [ ] the endpoint is public and needs no authentication
- [ ] it is not a password-reset or login-flow endpoint
- [ ] I have read the ethics section of the README
