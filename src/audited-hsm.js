import { PqHsm } from 'kxco-pq-hsm'
import { KxcoPqSdkError } from './errors.js'

export class AuditedHsm {
  #hsm
  #log

  constructor(hsm, auditLog) {
    if (!(hsm instanceof PqHsm)) throw new KxcoPqSdkError('hsm must be a PqHsm instance')
    if (!auditLog) throw new KxcoPqSdkError('auditLog is required')
    this.#hsm = hsm
    this.#log = auditLog
  }

  async keygen(label, alg = 'ml-dsa-65') {
    const result = await this.#hsm.keygen(label, alg)
    await this.#log.append('hsm:keygen', { label, alg })
    return result
  }

  async sign(label, message) {
    const result = await this.#hsm.sign(label, message)
    await this.#log.append('hsm:sign', { label, messageLength: message.length })
    return result
  }

  async decapsulate(label, ciphertext) {
    const result = await this.#hsm.decapsulate(label, ciphertext)
    await this.#log.append('hsm:decapsulate', { label })
    return result
  }

  async getPublicKey(label) {
    return this.#hsm.getPublicKey(label)
  }

  async listKeys() {
    return this.#hsm.listKeys()
  }

  async deleteKey(label) {
    // Log before deletion so the entry exists even if deletion throws
    await this.#log.append('hsm:deleteKey', { label })
    return this.#hsm.deleteKey(label)
  }
}
