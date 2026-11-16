import OpenAI from "openai";

const openai = new OpenAI({ apiKey: Deno.env.get("OPENAI_API_KEY") });

Deno.serve(async (req) => {
  const { patient, profile } = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-5-mini",
    messages: [
      { role: "system", content: "You write short care summaries." },
      { role: "user", content: `Patient ${patient.full_name}, born ${patient.date_of_birth}, NI ${patient.national_insurance_number}` },
      { role: "user", content: JSON.stringify(profile) },
    ],
  });
  return new Response(completion.choices[0].message.content);
});
