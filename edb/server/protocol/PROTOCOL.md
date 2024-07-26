```
struct AuthenticationOk {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 status = 0;   // Specifies that the authentication was successful.
}

struct AuthenticationKerberosV5 {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 status = 2;   // Specifies that Kerberos V5 authentication is required.
}

struct AuthenticationCleartextPassword {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 status = 3;   // Specifies that a clear-text password is required.
}

struct AuthenticationMD5Password {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 12;    // Length of message contents in bytes, including self.
    int32 status = 5;   // Specifies that an MD5-encrypted password is required.
    uint8[4] salt;      // The salt to use when encrypting the password.
}

struct AuthenticationGSS {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 status = 7;   // Specifies that GSSAPI authentication is required.
}

struct AuthenticationGSSContinue {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen;         // Length of message contents in bytes, including self.
    int32 status = 8;   // Specifies that this message contains GSSAPI or SSPI data.
    array<uint8> data;  // GSSAPI or SSPI authentication data.
}

struct AuthenticationSSPI {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 status = 9;   // Specifies that SSPI authentication is required.
}

struct AuthenticationSASL {
    uint8 mtype = 'R';          // Identifies the message as an authentication request.
    int32 mlen;                 // Length of message contents in bytes, including self.
    int32 status = 10;          // Specifies that SASL authentication is required.
    ztarray<string> mechanisms; // List of SASL authentication mechanisms, terminated by a zero byte.
}

struct AuthenticationSASLContinue {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen;         // Length of message contents in bytes, including self.
    int32 status = 11;  // Specifies that this message contains a SASL challenge.
    array<uint8> data;  // SASL data, specific to the SASL mechanism being used.
}

struct AuthenticationSASLFinal {
    uint8 mtype = 'R';  // Identifies the message as an authentication request.
    int32 mlen;         // Length of message contents in bytes, including self.
    int32 status = 12;  // Specifies that SASL authentication has completed.
    array<uint8> data;  // SASL outcome "additional data", specific to the SASL mechanism being used.
}

struct BackendKeyData {
    uint8 mtype = 'K';  // Identifies the message as cancellation key data.
    int32 mlen = 12;    // Length of message contents in bytes, including self.
    int32 pid;          // The process ID of this backend.
    int32 key;          // The secret key of this backend.
}

struct Bind {
    uint8 mtype = 'B';                     // Identifies the message as a Bind command.
    int32 mlen;                            // Length of message contents in bytes, including self.
    string portal;                         // The name of the destination portal.
    string statement;                      // The name of the source prepared statement.
    array<int16, int16> formatCodes;       // The parameter format codes.
    array<int16, ParamValue> values;       // Array of parameter values and their lengths.
    array<int16, int16> resultFormatCodes; // The result-column format codes.
}

struct BindComplete {
    uint8 mtype = '2';  // Identifies the message as a Bind-complete indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct CancelRequest {
    int32 mlen = 16;    // Length of message contents in bytes, including self.
    int32 code = 80877102; // The cancel request code.
    int32 pid;          // The process ID of the target backend.
    int32 key;          // The secret key for the target backend.
}

struct Close {
    uint8 mtype = 'C';  // Identifies the message as a Close command.
    int32 mlen;         // Length of message contents in bytes, including self.
    uint8 type;         // 'S' to close a prepared statement; 'P' to close a portal.
    string name;        // The name of the prepared statement or portal to close.
}

struct CloseComplete {
    uint8 mtype = '3';  // Identifies the message as a Close-complete indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct CommandComplete {
    uint8 mtype = 'C';  // Identifies the message as a command-completed response.
    int32 mlen;         // Length of message contents in bytes, including self.
    string tag;         // The command tag.
}

struct CopyData {
    uint8 mtype = 'd';  // Identifies the message as COPY data.
    int32 mlen;         // Length of message contents in bytes, including self.
    array<uint8> data;  // Data that forms part of a COPY data stream.
}

struct CopyDone {
    uint8 mtype = 'c';  // Identifies the message as a COPY-complete indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct CopyFail {
    uint8 mtype = 'f';  // Identifies the message as a COPY-failure indicator.
    int32 mlen;         // Length of message contents in bytes, including self.
    string errorMsg;    // An error message to report as the cause of failure.
}

struct CopyInResponse {
    uint8 mtype = 'G';               // Identifies the message as a Start Copy In response.
    int32 mlen;                      // Length of message contents in bytes, including self.
    int8 format;                     // 0 for textual, 1 for binary.
    array<int16, int16> formatCodes; // The format codes for each column.
}

struct CopyOutResponse {
    uint8 mtype = 'H';               // Identifies the message as a Start Copy Out response.
    int32 mlen;                      // Length of message contents in bytes, including self.
    int8 format;                     // 0 for textual, 1 for binary.
    array<int16, int16> formatCodes; // The format codes for each column.
}

struct CopyBothResponse {
    uint8 mtype = 'W';               // Identifies the message as a Start Copy Both response.
    int32 mlen;                      // Length of message contents in bytes, including self.
    int8 format;                     // 0 for textual, 1 for binary.
    array<int16, int16> formatCodes; // The format codes for each column.
}

struct DataRow {
    uint8 mtype = 'D';                 // Identifies the message as a data row.
    int32 mlen;                        // Length of message contents in bytes, including self.
    array<int16, ParamValue> values;   // Array of column values and their lengths.
}

struct Describe {
    uint8 mtype = 'D';  // Identifies the message as a Describe command.
    int32 mlen;         // Length of message contents in bytes, including self.
    uint8 type;         // 'S' to describe a prepared statement; 'P' to describe a portal.
    string name;        // The name of the prepared statement or portal.
}

struct EmptyQueryResponse {
    uint8 mtype = 'I';  // Identifies the message as a response to an empty query string.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct ErrorResponse {
    uint8 mtype = 'E';  // Identifies the message as an error.
    int32 mlen;         // Length of message contents in bytes, including self.
    ztarray<ErrorField> fields; // Array of error fields and their values.
}

struct ErrorField {
    uint8 type;    // A code identifying the field type.
    string value;  // The field value.
}

struct Execute {
    uint8 mtype = ‘E’;  // Identifies the message as an Execute command.
    int32 mlen;         // Length of message contents in bytes, including self.
    string portal;      // The name of the portal to execute.
    int32 maxRows;      // Maximum number of rows to return.
}

struct Flush {
    uint8 mtype = ‘H’;  // Identifies the message as a Flush command.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct FunctionCall {
    uint8 mtype = ‘F’;               // Identifies the message as a function call.
    int32 mlen;                      // Length of message contents in bytes, including self.
    int32 functionId;                // OID of the function to execute.
    array<int16, int16> formatCodes; // The parameter format codes.
    array<int16, ParamValue> args;   // Array of args and their lengths.
    int16 resultFormatCode; // The format code for the result.
}

struct FunctionCallResponse {
    uint8 mtype = ‘V’;  // Identifies the message as a function-call response.
    int32 mlen;         // Length of message contents in bytes, including self.
    ParamValue result;  // The function result value.
}

struct GSSENCRequest {
    uint8 mtype = 'F';                   // Identifies the message as a GSSAPI Encryption request.
    int32 mlen = 8;                      // Length of message contents in bytes, including self.
    int32 gssencRequestCode = 80877104;  // The GSSAPI Encryption request code.
}

struct GSSResponse {
    uint8 mtype = ‘p’;  // Identifies the message as a GSSAPI or SSPI response.
    int32 mlen;         // Length of message contents in bytes, including self.
    array<uint8> data;  // GSSAPI or SSPI authentication data.
}

struct NegotiateProtocolVersion {
    uint8 mtype = ‘v’;            // Identifies the message as a protocol version negotiation request.
    int32 mlen;                   // Length of message contents in bytes, including self.
    int32 minorVersion;           // Newest minor protocol version supported by the server.
    array<int32, string> options; // List of protocol options not recognized.
}

struct NoData {
    uint8 mtype = ‘n’;  // Identifies the message as a No Data indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct NoticeResponse {
    uint8 mtype = ‘N’;  // Identifies the message as a notice.
    int32 mlen;         // Length of message contents in bytes, including self.
    ztarray<NoticeField> fields; // Array of notice fields and their values.
}

struct NoticeField {
    uint8 type;    // A code identifying the field type.
    string value;  // The field value.
}

struct NotificationResponse {
    uint8 mtype = ‘A’;  // Identifies the message as a notification.
    int32 mlen;         // Length of message contents in bytes, including self.
    int32 pid;          // The process ID of the notifying backend.
    string channel;     // The name of the notification channel.
    string payload;     // The notification payload.
}

struct ParameterDescription {
    uint8 mtype = ‘t’;  // Identifies the message as a parameter description.
    int32 mlen;         // Length of message contents in bytes, including self.
    array<int16, int32> paramTypes; // OIDs of the parameter data types.
}

struct ParameterStatus {
    uint8 mtype = ‘S’;  // Identifies the message as a runtime parameter status report.
    int32 mlen;         // Length of message contents in bytes, including self.
    string name;        // The name of the parameter.
    string value;       // The current value of the parameter.
}

struct Parse {
    uint8 mtype = ‘P’;  // Identifies the message as a Parse command.
    int32 mlen;         // Length of message contents in bytes, including self.
    string statement;   // The name of the destination prepared statement.
    string query;       // The query string to be parsed.
    array<int16, int32> paramTypes; // OIDs of the parameter data types.
}

struct ParseComplete {
    uint8 mtype = ‘1’;  // Identifies the message as a Parse-complete indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct PasswordMessage {
    uint8 mtype = ‘p’;  // Identifies the message as a password response.
    int32 mlen;         // Length of message contents in bytes, including self.
    string password;    // The password (encrypted or plaintext, depending on context).
}

struct PortalSuspended {
    uint8 mtype = ‘s’;  // Identifies the message as a portal-suspended indicator.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct Query {
    uint8 mtype = ‘Q’;  // Identifies the message as a simple query command.
    int32 mlen;         // Length of message contents in bytes, including self.
    string query;       // The query string to be executed.
}

struct ReadyForQuery {
    uint8 mtype = ‘Z’;  // Identifies the message as a ready-for-query indicator.
    int32 mlen = 5;     // Length of message contents in bytes, including self.
    uint8 status;       // Current transaction status indicator.
}

struct RowDescription {
    uint8 mtype = ‘T’;  // Identifies the message as a row description.
    int32 mlen;         // Length of message contents in bytes, including self.
    array<int16, RowField> fields;     // Array of field descriptions.
}

struct RowField {
    string name;             // The field name
    uint32 tableOid;         // The table ID (OID) of the table the column is from, or 0 if not a column reference
    int16 columnAttrNumber;  // The attribute number of the column, or 0 if not a column reference
    uint32 dataTypeOid;      // The object ID of the field's data type
    int16 dataTypeSize;      // The data type size (negative if variable size)
    int32 typeModifier;      // The type modifier
    int16 formatCode;        // The format code being used for the field (0 for text, 1 for binary)
}

struct SASLInitialResponse {
    uint8 mtype = ‘p’;  // Identifies the message as a SASL initial response.
    int32 mlen;         // Length of message contents in bytes, including self.
    string mechanism;   // Name of the SASL authentication mechanism.
    array<int32, uint8> response;   // SASL initial response data.
}

struct SASLResponse {
    uint8 mtype = ‘p’;  // Identifies the message as a SASL response.
    int32 mlen;         // Length of message contents in bytes, including self.
    array<uint8> response;   // SASL response data.
}

struct SSLRequest {
    int32 mlen = 8;     // Length of message contents in bytes, including self.
    int32 code = 80877103; // The SSL request code.
}

struct StartupMessage {
    int32 mlen;         // Length of message contents in bytes, including self.
    int32 code = 196608; // The protocol version number.
    ztarray<string> params;    // List of parameter name-value pairs, terminated by a zero byte.
}

struct Sync {
    uint8 mtype = ‘S’;  // Identifies the message as a Sync command.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

struct Terminate {
    uint8 mtype = ‘X’;  // Identifies the message as a Terminate command.
    int32 mlen = 4;     // Length of message contents in bytes, including self.
}

```