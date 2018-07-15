import { HMAC } from 'fast-sha256'

export default function pbkdf2 (password, salt, iterations, dkLen) {
  const prf = new HMAC(password)
  const len = prf.digestLength
  const ctr = new Uint8Array(4)
  const t = new Uint8Array(len)
  const u = new Uint8Array(len)
  const dk = new Uint8Array(dkLen)

  for (let i = 0; i * len < dkLen; i++) {
    let c = i + 1
    ctr[0] = (c >>> 24) & 0xff
    ctr[1] = (c >>> 16) & 0xff
    ctr[2] = (c >>> 8) & 0xff
    ctr[3] = (c >>> 0) & 0xff
    prf.reset()
    prf.update(salt)
    prf.update(ctr)
    prf.finish(u)
    for (let j = 0; j < len; j++) {
      t[j] = u[j]
    }
    for (let j = 2; j <= iterations; j++) {
      prf.reset()
      prf.update(u).finish(u)
      for (let k = 0; k < len; k++) {
        t[k] ^= u[k]
      }
    }
    for (let j = 0; j < len && i * len + j < dkLen; j++) {
      dk[i * len + j] = t[j]
    }
  }
  for (let i = 0; i < len; i++) {
    t[i] = u[i] = 0
  }
  for (let i = 0; i < 4; i++) {
    ctr[i] = 0
  }
  prf.clean()
  return dk
}
