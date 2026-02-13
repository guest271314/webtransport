/**
 * Simple EventEmitter for browser environments.
 */
export class EventEmitter {
  constructor() {
    this._listeners = new Map();
  }

  on(event, listener) {
    if (!this._listeners.has(event)) {
      this._listeners.set(event, []);
    }
    this._listeners.get(event).push(listener);
    return this;
  }

  once(event, listener) {
    const wrapper = (...args) => {
      this.off(event, wrapper);
      listener.apply(this, args);
    };
    wrapper._original = listener;
    return this.on(event, wrapper);
  }

  off(event, listener) {
    const listeners = this._listeners.get(event);
    if (!listeners) return this;
    const idx = listeners.findIndex(l => l === listener || l._original === listener);
    if (idx !== -1) listeners.splice(idx, 1);
    return this;
  }

  emit(event, ...args) {
    const listeners = this._listeners.get(event);
    if (!listeners) return false;
    for (const listener of [...listeners]) {
      try {
        listener.apply(this, args);
      } catch (e) {
        console.error(`EventEmitter error in '${event}':`, e);
      }
    }
    return true;
  }

  removeAllListeners(event) {
    if (event) {
      this._listeners.delete(event);
    } else {
      this._listeners.clear();
    }
    return this;
  }
}