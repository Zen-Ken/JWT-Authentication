# Exploiting the None Algorithm

In the code below you can see no algorithm provided in the `.verify` method. In the `jsonwebtoken` library if no algorithm is specified it trusts the alg in the JWT header.

```javascript
jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
  if (err) return res.sendStatus(403);
  req.user = decoded;
  next();
});
```

When a JWT with the header with an `alg: "none"` the JWT is not signed. This bypasses the secret as there's no signature to verify.

| NOTE: Example is hypothetical for education purposes

## Addressing the Vulnerability

We can implement an algorithm 'whitelist' which says what algorithms are accepted. This prevents verifying the signature using the `none` algorithm, since it's not included in the array.

```javascript
jwt.verify(
  token,
  process.env.ACCESS_TOKEN_SECRET,
  { algorithms: ["RS256"] },
  (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.user = decoded;
    next();
  }
);
```
