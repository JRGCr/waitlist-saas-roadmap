export interface Env {
  DB: D1Database;
  ANALYTICS_SECRET: string;
  ALLOWED_ORIGIN: string;
  WAITLIST_CONFIG: string;
  TURNSTILE_SECRET_KEY?: string;
}

interface WaitlistConfig {
  cors_mode: 'strict' | 'open' | 'custom';
  cors_origins?: string[];
}

function getCorsHeaders(request: Request, env: Env): Record<string, string> {
  const config: WaitlistConfig = JSON.parse(env.WAITLIST_CONFIG || '{"cors_mode":"open"}');
  const origin = request.headers.get('Origin');
  
  const baseHeaders = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
  
  switch (config.cors_mode) {
    case 'strict':
      if (origin === env.ALLOWED_ORIGIN) {
        return { ...baseHeaders, 'Access-Control-Allow-Origin': origin };
      }
      return baseHeaders;
    
    case 'custom':
      const allowedOrigins = config.cors_origins || [];
      if (origin === env.ALLOWED_ORIGIN || (origin && allowedOrigins.includes(origin))) {
        return { ...baseHeaders, 'Access-Control-Allow-Origin': origin };
      }
      return baseHeaders;
    
    case 'open':
    default:
      return { ...baseHeaders, 'Access-Control-Allow-Origin': '*' };
  }
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function verifyTurnstile(token: string, secretKey: string, ip: string | null): Promise<boolean> {
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: secretKey,
      response: token,
      remoteip: ip
    })
  });
  
  const result = await response.json() as any;
  return result.success === true;
}

function validateAnalyticsSecret(request: Request, secret: string): { valid: boolean; method: 'header' | 'query' | 'none' } {
  const authHeader = request.headers.get('Authorization');
  if (authHeader === `Bearer ${secret}`) {
    return { valid: true, method: 'header' };
  }
  
  const url = new URL(request.url);
  if (url.searchParams.get('secret') === secret) {
    console.log('Analytics accessed via query param - consider using header auth');
    return { valid: true, method: 'query' };
  }
  
  return { valid: false, method: 'none' };
}

async function handleSignup(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  try {
    const body = await request.json() as any;
    
    if (body.website) {
      return Response.json({ success: true }, { headers: corsHeaders });
    }
    
    if (env.TURNSTILE_SECRET_KEY && body.turnstile_token) {
      const turnstileValid = await verifyTurnstile(
        body.turnstile_token,
        env.TURNSTILE_SECRET_KEY,
        request.headers.get('CF-Connecting-IP')
      );
      if (!turnstileValid) {
        return Response.json({ error: 'Verification failed' }, { status: 400, headers: corsHeaders });
      }
    }
    
    if (!body.email || !isValidEmail(body.email)) {
      return Response.json({ error: 'Valid email required' }, { status: 400, headers: corsHeaders });
    }
    
    await env.DB.prepare(`
      INSERT INTO signups (
        email, name, company, phone, job_title, use_case,
        company_size, industry, budget, expected_usage, country,
        linkedin, twitter, current_solution, referral_source,
        ip_address, user_agent
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      body.email,
      body.name || null,
      body.company || null,
      body.phone || null,
      body.job_title || null,
      body.use_case || null,
      body.company_size || null,
      body.industry || null,
      body.budget || null,
      body.expected_usage || null,
      body.country || null,
      body.linkedin || null,
      body.twitter || null,
      body.current_solution || null,
      body.referral_source || null,
      request.headers.get('CF-Connecting-IP'),
      request.headers.get('User-Agent')
    ).run();
    
    return Response.json({ success: true }, { headers: corsHeaders });
    
  } catch (error: any) {
    if (error.message?.includes('UNIQUE constraint')) {
      return Response.json({ success: true }, { headers: corsHeaders });
    }
    
    return Response.json({ error: 'Internal error' }, { status: 500, headers: corsHeaders });
  }
}

async function handleAnalytics(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const auth = validateAnalyticsSecret(request, env.ANALYTICS_SECRET);
  if (!auth.valid) {
    return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });
  }
  
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  
  const total = await env.DB.prepare('SELECT COUNT(*) as count FROM signups').first<{ count: number }>();
  const todayCount = await env.DB.prepare('SELECT COUNT(*) as count FROM signups WHERE date(created_at) = ?').bind(today).first<{ count: number }>();
  const weekCount = await env.DB.prepare('SELECT COUNT(*) as count FROM signups WHERE created_at >= ?').bind(weekAgo).first<{ count: number }>();
  const monthCount = await env.DB.prepare('SELECT COUNT(*) as count FROM signups WHERE created_at >= ?').bind(monthAgo).first<{ count: number }>();
  const recent = await env.DB.prepare('SELECT email, name, created_at FROM signups ORDER BY created_at DESC LIMIT 10').all();
  
  return Response.json({
    total_signups: total?.count || 0,
    signups_today: todayCount?.count || 0,
    signups_this_week: weekCount?.count || 0,
    signups_this_month: monthCount?.count || 0,
    recent_signups: recent.results
  }, { headers: corsHeaders });
}

async function handleSignupsExport(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
  const auth = validateAnalyticsSecret(request, env.ANALYTICS_SECRET);
  if (!auth.valid) {
    return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });
  }
  
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 1000);
  const format = url.searchParams.get('format') || 'json';
  const since = url.searchParams.get('since');
  const offset = (page - 1) * limit;
  
  let whereClause = '';
  const params: any[] = [];
  
  if (since) {
    whereClause = 'WHERE created_at >= ?';
    params.push(since);
  }
  
  const countQuery = `SELECT COUNT(*) as count FROM signups ${whereClause}`;
  const total = await env.DB.prepare(countQuery).bind(...params).first<{ count: number }>();
  
  const dataQuery = `
    SELECT 
      id, email, name, company, phone, job_title, use_case,
      company_size, industry, budget, expected_usage, country,
      linkedin, twitter, current_solution, referral_source, created_at 
    FROM signups ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `;
  const signups = await env.DB.prepare(dataQuery).bind(...params, limit, offset).all();
  
  if (format === 'csv') {
    const csv = [
      'id,email,name,company,phone,job_title,use_case,company_size,industry,budget,expected_usage,country,linkedin,twitter,current_solution,referral_source,created_at',
      ...signups.results.map((s: any) => 
        `${s.id},"${s.email}","${s.name || ''}","${s.company || ''}","${s.phone || ''}","${s.job_title || ''}","${s.use_case || ''}","${s.company_size || ''}","${s.industry || ''}","${s.budget || ''}","${s.expected_usage || ''}","${s.country || ''}","${s.linkedin || ''}","${s.twitter || ''}","${s.current_solution || ''}","${s.referral_source || ''}","${s.created_at}"`
      )
    ].join('\n');
    
    return new Response(csv, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="signups-${Date.now()}.csv"`
      }
    });
  }
  
  return Response.json({
    signups: signups.results,
    total: total?.count || 0,
    page,
    pages: Math.ceil((total?.count || 0) / limit)
  }, { headers: corsHeaders });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request, env);
    
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    if (url.pathname === '/signup' && request.method === 'POST') {
      return handleSignup(request, env, corsHeaders);
    }
    
    if (url.pathname === '/analytics' && request.method === 'GET') {
      return handleAnalytics(request, env, corsHeaders);
    }
    
    if (url.pathname === '/signups' && request.method === 'GET') {
      return handleSignupsExport(request, env, corsHeaders);
    }
    
    return new Response('Not Found', { status: 404, headers: corsHeaders });
  }
};