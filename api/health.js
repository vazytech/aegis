export const config = {
  runtime: 'edge',
};

export default function handler(request) {
  return new Response(
    JSON.stringify({ status: 'ok', message: 'AEGIS Scanner Backend Active' }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
