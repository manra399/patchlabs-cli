const ALLOWED = ["https://app.example.com"];
export default function handler(req, res) {
  const allowed = ALLOWED.includes(req.headers.origin) ? req.headers.origin : ALLOWED[0];
  res.setHeader("Access-Control-Allow-Origin", allowed);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.json({ user: req.cookies.session });
}
