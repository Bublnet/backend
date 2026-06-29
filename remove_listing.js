// remove_listing.js
// Orchestrates full deletion of a venue across Supabase DB, Firebase (Firestore mock), and CDN storage.

import { supabaseAdmin } from './supabase.client.js';
import { db } from './firebase.config.js';
import { removeBucketImages } from './remove_bucket_image.js';

/**
 * Delete a venue listing completely.
 * @param {string} venueId - Primary key of the venue (Supabase "id" column).
 */
export async function removeListing(venueId) {
  if (!venueId) throw new Error('venueId is required');

  // 1️⃣ Fetch the venue record to get image URLs.
  const { data: venue, error: fetchErr } = await supabaseAdmin
    .from('venues')
    .select('*')
    .eq('id', venueId)
    .maybeSingle();

  if (fetchErr) {
    console.error('Failed to fetch venue for deletion', fetchErr);
    throw fetchErr;
  }

  // 2️⃣ Remove associated images from all buckets.
  if (venue) {
    try {
      await removeBucketImages(venue);
    } catch (e) {
      console.warn('Image cleanup failed (continuing)', e);
    }
  }

  // 3️⃣ Delete the venue row from Supabase.
  const { error: deleteSupabaseErr } = await supabaseAdmin
    .from('venues')
    .delete()
    .eq('id', venueId);

  if (deleteSupabaseErr) {
    console.error('Supabase venue delete failed', deleteSupabaseErr);
    // Continue to attempt Firebase cleanup.
  } else {
    console.log(`Supabase venue ${venueId} deleted`);
  }

  // 4️⃣ Delete the Firestore document (backend representation).
  try {
    await db.collection('venues').doc(venueId).delete();
    console.log(`Firebase venue ${venueId} deleted`);
  } catch (e) {
    console.warn('Firebase venue delete failed (continuing)', e);
  }

  // 5️⃣ Placeholder for payment‑related cleanup – to be implemented when payment schema is ready.
}
