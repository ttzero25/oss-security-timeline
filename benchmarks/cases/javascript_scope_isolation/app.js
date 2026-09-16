function read(req) {
  const value = req.body.value;
  return value;
}

function fixed() {
  return eval("2 + 2");
}
