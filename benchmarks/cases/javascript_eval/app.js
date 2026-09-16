function run(req) {
  const code = req.body.code;
  return eval(code);
}
