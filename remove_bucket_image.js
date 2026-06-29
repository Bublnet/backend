// remove_bucket_image.js
// Utility to delete associated images of a venue from Supabase storage buckets.
// Expects a venue record containing URLs for hd, thumb, 100px and logo images.
// It extracts the storage paths from the public URLs and removes the objects.

import { supabaseAdmin } from './supabase.client.js';

/**
 * Extract the storage path from a Supabase public URL.
 * Supabase public URLs look like: https://<project>.supabase.co/storage/v1/object/public/<bucket>/<path>
 * We need the <path> part to pass to storage.from(bucket).remove([...]).
 */
function extractPath(publicUrl) {
  try {
    const url = new URL(publicUrl);
    const parts = url.pathname.split('/');
    const bucketIndex = parts.indexOf('public') + 1;
    const bucket = parts[bucketIndex];
    const path = parts.slice(bucketIndex + 1).join('/');
    return { bucket, path };
  } catch (e) {
    console.warn('Failed to parse public URL', publicUrl, e);
    return null;
  }
}

export async function removeBucketImages(venue) {
  if (!venue) return;
  const candidates = [];
  const urlFields = ['hd', 'thumb', 'icon100', 'logo'];
  for (const field of urlFields) {
    const url = venue[field];
    if (url && typeof url === 'string') {
      const info = extractPath(url);
      if (info) candidates.push({ bucket: info.bucket, path: info.path });
    }
  }
  const byBucket = candidates.reduce((acc, cur) => {
    (acc[cur.bucket] = acc[cur.bucket] || []).push(cur.path);
    return acc;
  }, {});
  for (const [bucket, paths] of Object.entries(byBucket)) {
    try {
      const { error } = await supabaseAdmin.storage.from(bucket).remove(paths);
      if (error) console.error(`Failed to delete images from bucket ${bucket}:`, error);
    } catch (e) {
      console.error(`Exception while deleting from bucket ${bucket}:`, e);
    }
  }
}
