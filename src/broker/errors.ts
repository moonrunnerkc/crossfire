export class BrokerError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "BrokerError";
  }
}
