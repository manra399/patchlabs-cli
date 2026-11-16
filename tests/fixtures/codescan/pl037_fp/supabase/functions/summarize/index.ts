import OpenAI from "openai";

const openai = new OpenAI({ apiKey: Deno.env.get("OPENAI_API_KEY") });

Deno.serve(async (req) => {
  const { ticketText, user } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-5-mini",
    messages: [
      { role: "system", content: "Summarise the support ticket. Names and emails are replaced with [NAME] and [EMAIL]." },
      { role: "user", content: ticketText },
    ],
  });
  const summary = completion.choices[0].message.content;
  return Response.json({ summary, to: user.email });
});
