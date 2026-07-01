import { supabaseAdmin } from '../supabase.client.js';

/**
 * Logs an analytics event to Supabase
 */
export async function logAnalyticsEvent({
  serviceName,
  eventType,
  eventName,
  userId = null,
  sessionId = null,
  ipAddress = null,
  country = null,
  state = null,
  city = null,
  userAgent = null,
  deviceType = null,
  venueId = null,
  venueSpeciality = null,
  route = null,
  method = null,
  statusCode = null,
  responseTimeMs = null,
  metadata = {}
}) {
  if (!supabaseAdmin) return;

  try {
    await supabaseAdmin.from('analytics_events').insert({
      service_name: serviceName,
      event_type: eventType,
      event_name: eventName,
      user_id: userId,
      session_id: sessionId,
      ip_address: ipAddress,
      country: country,
      state: state,
      city: city,
      user_agent: userAgent,
      device_type: deviceType,
      venue_id: venueId,
      venue_speciality: venueSpeciality,
      route: route,
      method: method,
      status_code: statusCode,
      response_time_ms: responseTimeMs,
      metadata
    });
  } catch (error) {
    console.error(`[Analytics] Failed to log event ${eventName}:`, error);
  }
}

/**
 * Express middleware to track backend traffic
 */
export function analyticsMiddleware(serviceName) {
  return (req, res, next) => {
    const start = Date.now();
    
    // We can infer some location data if we are behind Cloudflare/Vercel
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const country = req.headers['cf-ipcountry'] || req.headers['x-vercel-ip-country'];
    const state = req.headers['x-vercel-ip-country-region'];
    const city = req.headers['x-vercel-ip-city'];
    const userAgent = req.headers['user-agent'];
    const deviceType = userAgent?.includes('Mobile') ? 'Mobile' : 'Desktop';

    res.on('finish', () => {
      const responseTimeMs = Date.now() - start;
      const statusCode = res.statusCode;
      
      // Determine if it's suspicious
      let eventType = 'api_request';
      if (statusCode === 401 || statusCode === 403 || statusCode === 429) {
        eventType = 'suspicious_activity';
      }

      logAnalyticsEvent({
        serviceName,
        eventType,
        eventName: 'incoming_request',
        userId: req.auth?.user?.id, 
        ipAddress,
        country,
        state,
        city,
        userAgent,
        deviceType,
        route: req.originalUrl,
        method: req.method,
        statusCode,
        responseTimeMs
      });
    });

    next();
  };
}

/**
 * Custom function to log specific suspicious activities
 */
export function logSuspiciousActivity(serviceName, reason, req) {
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  logAnalyticsEvent({
    serviceName,
    eventType: 'suspicious_activity',
    eventName: reason,
    userId: req.auth?.user?.id,
    ipAddress,
    route: req.originalUrl,
    method: req.method,
    userAgent: req.headers['user-agent']
  });
}
