import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const url = process.env.SUPABASE_URL || '';
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

export const isSupabaseAuthConfigured = Boolean(url && serviceKey);

export const supabaseAdmin = isSupabaseAuthConfigured
  ? createClient(url, serviceKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    })
  : null;

export const validRoles = new Set(['admin', 'staff', 'host', 'hoststaff', 'client']);

export function normalizeRole(role) {
  const value = String(role || '').trim().toLowerCase();
  return validRoles.has(value) ? value : 'client';
}

export async function getSupabaseIdentity(token) {
  if (!supabaseAdmin) {
    const error = new Error('Supabase Auth is not configured.');
    error.status = 503;
    throw error;
  }
  const { data: authData, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !authData?.user) {
    const error = new Error('Session expired. Please login again.');
    error.status = 401;
    throw error;
  }
  const authUser = authData.user;
  const { data: storedProfile, error: profileError } = await supabaseAdmin
    .from('profiles')
    .select('*')
    .eq('id', authUser.id)
    .maybeSingle();
  if (profileError) throw profileError;

  console.log('DEBUG role info:', { 
    userMetadata: authUser.user_metadata, 
    storedProfileRole: storedProfile?.role 
  });
  const profile = {
    id: authUser.id,
    email: authUser.email || storedProfile?.email || '',
    identifier: authUser.email || storedProfile?.email || '',
    name: storedProfile?.display_name || authUser.user_metadata?.name || authUser.email?.split('@')[0] || 'Dvenue User',
    role: normalizeRole(storedProfile?.role && storedProfile.role !== 'client' ? storedProfile.role : (authUser.user_metadata?.role || storedProfile?.role)),
    parentId: storedProfile?.parent_id || null,
    permissions: storedProfile?.permissions || {},
    active: storedProfile?.active !== false,
    isPremium: storedProfile?.is_premium === true,
    adAccessUntil: storedProfile?.ad_access_until || null,
    manualLocation: storedProfile?.manual_location || null,
  };
  if (!storedProfile) {
    const { error: insertError } = await supabaseAdmin.from('profiles').insert({
      id: authUser.id,
      email: profile.email,
      display_name: profile.name,
      role: 'client',
    });
    if (insertError) throw insertError;
  }
  if (!profile.active) {
    const error = new Error('This account has been disabled.');
    error.status = 403;
    throw error;
  }
  return { authUser, profile };
}
