"""Allowlisted TLS error indicators, not raw errors or asserted root causes."""
import re
MAX_ERROR_CHARS=16384
INDICATORS={
 'AlertUnknownCA':('tlsv1 alert unknown ca','tlsv1_alert_unknown_ca'),
 'AlertBadCertificate':('sslv3 alert bad certificate','sslv3_alert_bad_certificate','tlsv1 alert bad certificate','ssl/tls alert bad certificate'),
 'AlertCertificateUnknown':('sslv3 alert certificate unknown','sslv3_alert_certificate_unknown'),
 'AlertCertificateExpired':('sslv3 alert certificate expired','sslv3_alert_certificate_expired'),
 'AlertProtocolVersion':('tlsv1 alert protocol version','tlsv1_alert_protocol_version'),
 'AlertHandshakeFailure':('sslv3 alert handshake failure','sslv3_alert_handshake_failure'),
 'TLSVersionDisagreementReported':('client and mitmproxy cannot agree on a tls version to use','the remote server and mitmproxy cannot agree on a tls version to use'),
 'ClientHelloParseError':('cannot parse clienthello',),
 'HandshakeDisconnectReported':('the client disconnected during the handshake','connection closed early'),
 'LocalCertificateVerifyFailure':('certificate verify failed','certificate_verify_failed'),
 'LocalNoSharedCipher':('no shared cipher','no_shared_cipher'),
 'TransportUnexpectedEOF':('unexpected eof','unexpected_eof'),
 'TransportConnectionReset':('connection reset by peer','wsaeconnreset'),
 'TransportTimeout':('timed out','timeout'),
}
def classify(error):
 if not isinstance(error,str) or not error:
  return {'ErrorTextAvailable':False,'ErrorScanTruncated':False,'ErrorIndicators':[],'IndicatorStatus':'Unavailable'}
 text=error[:MAX_ERROR_CHARS].lower()
 labels=[label for label,phrases in INDICATORS.items() if any(re.search(r'(?<![a-z0-9_])'+re.escape(s)+r'(?![a-z0-9_])',text) for s in phrases)]
 return {'ErrorTextAvailable':True,'ErrorScanTruncated':len(error)>MAX_ERROR_CHARS,'ErrorIndicators':sorted(labels),'IndicatorStatus':'AllowlistedIndicatorsPresent' if labels else 'NoAllowlistedIndicator'}
def failure_record(side,data,scope_authorized):
 # No repr(), exception text, connection ID, SNI, hostname, URL or certificate subject exported.
 context=data.context;client=context.client;server=context.server
 conn=client if side=='Client' else server
 result={'Side':side,'ScopedClientHelloAuthorized':bool(scope_authorized),'ClientTLSEstablished':bool(getattr(client,'tls_established',False)),'ServerTLSEstablished':bool(getattr(server,'tls_established',False)),'RawErrorStored':False,'RootCauseEstablished':False,'PinningEstablished':False}
 result.update(classify(getattr(conn,'error',None)) if scope_authorized else classify(None))
 return result
