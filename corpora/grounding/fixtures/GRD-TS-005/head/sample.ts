export class ServiceAccount {
  private _token: string;

  constructor(token: string) {
    this._token = token.trim();
  }

  get token(): string {
    return this._token;
  }
}
