import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { supabaseAdmin } from './supabase.client.js';

export const hasFirebaseServerCredentials = true;
export const firebaseConfig = { apiKey: 'dummy', projectId: 'dummy' };

export function initFirebaseAdmin() { return true; }

class FirestoreBatch {
  constructor(client) { this.client = client; this.ops = []; }
  set(ref, data, opts) { this.ops.push({ type: 'set', ref, data, opts }); }
  async commit() {
    for (const op of this.ops) {
      if (op.type === 'set') {
        await op.ref.set(op.data, op.opts);
      }
    }
  }
}

class FirestoreDoc {
  constructor(table, id, supabaseClient) {
    this.table = table;
    this.id = id;
    this.supabaseClient = supabaseClient;
  }
  collection(subTable) {
    if (this.table === 'venues' && subTable === 'priceHistory') return new FirestoreCollection('venue_price_history', this.supabaseClient);
    return new FirestoreCollection(`${this.table}_${subTable}`, this.supabaseClient);
  }
  async get() {
    console.log(`[DB READ] Fetching ${this.table} with ID: ${this.id}`);
    const { data, error } = await this.supabaseClient.from(this.table).select('*').eq('id', this.id).maybeSingle();
    if (error) {
      console.error(`[DB READ ERROR] Mock Firestore error getting ${this.table}/${this.id}:`, error);
      throw error;
    }
    console.log(`[DB READ SUCCESS] Fetched ${this.table}/${this.id}, found: ${!!data}`);
    return {
      exists: !!data,
      id: this.id,
      data: () => data || {}
    };
  }
  async set(data, options = {}) {
    // If not merging, we should theoretically overwrite, but upsert with merge is safer
    // for most of our use cases unless specified. Supabase upsert will merge.
    const cleanData = Object.fromEntries(Object.entries(data).filter(([_, v]) => v !== undefined));
    const { error } = await this.supabaseClient.from(this.table).upsert({ id: this.id, ...cleanData });
    if (error) {
      console.error(`Mock Firestore error setting ${this.table}/${this.id}:`, error);
      throw error;
    }
  }
  async delete() {
    const { error } = await this.supabaseClient.from(this.table).delete().eq('id', this.id);
    if (error) throw error;
  }
}

class FirestoreQuery {
  constructor(table, supabaseClient) {
    this.table = table;
    this.supabaseClient = supabaseClient;
    this._where = [];
    this._orderBy = [];
    this._limit = null;
  }
  where(field, op, value) {
    this._where.push({ field, op, value });
    return this;
  }
  limit(n) {
    this._limit = n;
    return this;
  }
  orderBy(field, dir = 'asc') {
    this._orderBy.push({ field, dir });
    return this;
  }
  async get() {
    let q = this.supabaseClient.from(this.table).select('*');
    for (const w of this._where) {
      if (w.op === '==') q = q.eq(w.field, w.value);
      else if (w.op === '>=') q = q.gte(w.field, w.value);
      else if (w.op === '<=') q = q.lte(w.field, w.value);
      else if (w.op === '<') q = q.lt(w.field, w.value);
      else if (w.op === '>') q = q.gt(w.field, w.value);
      else if (w.op === 'in') q = q.in(w.field, w.value);
      else if (w.op === 'array-contains') q = q.contains(w.field, [w.value]);
    }
    for (const o of this._orderBy) {
      q = q.order(o.field, { ascending: o.dir === 'asc' });
    }
    if (this._limit !== null) q = q.limit(this._limit);
    const { data, error } = await q;
    if (error) {
      console.error(`Mock Firestore query error on ${this.table}:`, error);
      throw error;
    }
    return {
      empty: data.length === 0,
      docs: data.map(d => ({
        id: d.id,
        exists: true,
        data: () => d
      }))
    };
  }
}

class FirestoreCollection extends FirestoreQuery {
  doc(id) {
    return new FirestoreDoc(this.table, id, this.supabaseClient);
  }
  async add(data) {
    const cleanData = Object.fromEntries(Object.entries(data).filter(([_, v]) => v !== undefined));
    if (!cleanData.id) {
      cleanData.id = crypto.randomUUID();
    }
    console.log(`[DB WRITE] Inserting into ${this.table} with ID: ${cleanData.id}`);
    const { data: res, error } = await this.supabaseClient.from(this.table).insert(cleanData).select().single();
    if (error) {
      console.error(`[DB WRITE ERROR] Failed to insert into ${this.table}:`, error);
      throw error;
    }
    console.log(`[DB WRITE SUCCESS] Inserted into ${this.table}, returned ID: ${res?.id}`);
    return new FirestoreDoc(this.table, res.id, this.supabaseClient);
  }
}

class FirestoreMock {
  constructor(supabaseClient) {
    this.supabaseClient = supabaseClient;
  }
  collection(name) {
    const tableMap = { 'users': 'profiles', 'adminSessions': 'admin_sessions', 'authOtps': 'auth_otps', 'venues': 'venues', 'bookings': 'bookings', 'settings': 'settings' };
    return new FirestoreCollection(tableMap[name] || name, this.supabaseClient);
  }
  batch() {
    return new FirestoreBatch(this.supabaseClient);
  }
}

export const db = new FirestoreMock(supabaseAdmin);

export const auth = {
  verifyIdToken: async (token) => {
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) throw new Error('Invalid token');
    return { uid: data.user.id, email: data.user.email, exp: Math.floor(Date.now() / 1000) + 3600 };
  }
};

export const storage = null;
