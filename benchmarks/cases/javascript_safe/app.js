function greet(req) {
  const name = req.body.name;
  return `hello ${name}`;
}
