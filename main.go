package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cat myca.crt | openssl x509 -hash -noout

func main() {
	openssl_hash()
}

func openssl_hash() {
	cmd := exec.Command("openssl", "x509", "-hash", "-noout")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stdin = strings.NewReader(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----
`)

	err := cmd.Run()

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out.String())
}

func X509_NAME_hash(principal string) (int, error) {
	return X509_NAME_hashWithAlgorithm(principal, "SHA1")
}

func X509_NAME_hashWithAlgorithm(principal string, algorithm string) (int, error) {
	princ := []byte(principal)
	obj := new(asn1.RawValue)
	_, err := asn1.Unmarshal(princ, obj)
	if err != nil {
		return 0, err
	}

	// Remove the leading sequence ...
	toHash, err := asn1.Marshal(obj)
	if err != nil {
		return 0, err
	}

	md, err := getHashAlgorithm(algorithm)
	if err != nil {
		return 0, err
	}

	digest := md.Sum(toHash)
	return bits.LeadingZeros32(uint32(digest[0])<<24 | uint32(digest[1])<<16 | uint32(digest[2])<<8 | uint32(digest[3])), nil
}

func getHashAlgorithm(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "SHA1":
		return sha1.New(), nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func main9() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----
`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Example usage
	hashValue, err := X509_NAME_hash(string(cert.RawSubject))
	if err != nil {
		panic(err)
	}
	println(hashValue)
}

func main8() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----
`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	subject := pkix.Name{
		CommonName:   strings.ToLower(cert.Subject.CommonName),
		Organization: []string{strings.ToLower(cert.Subject.Organization[0])},
		//Country:       ,
		//Locality:      ,
		//Province:      []string{"California"},
		//StreetAddress: []string{"1600 Amphitheatre Pkwy"},
	}

	// Encode the name to DER bytes
	derBytes, err := asn1.Marshal(subject)
	if err != nil {
		fmt.Println("Error encoding name:", err)
		return
	}

	// Print the DER bytes in hexadecimal format (optional)
	fmt.Printf("DER bytes: %x\n", derBytes)
	fmt.Printf("DER bytes: %x\n", derBytes)

	// Calculate the SHA-1 hash of the SPKI
	hash := sha1.Sum(derBytes)

	// Print the hash in hexadecimal format
	fmt.Println(hex.EncodeToString(hash[:]))
}

// X509_NAME_hash_ex calculates the hash of an X.509 subject name.
func X509_NAME_hash_ex(name string) string {
	// Normalize the name (remove spaces and convert to lowercase)
	name = strings.ToLower(strings.ReplaceAll(name, " ", ""))

	// Calculate the SHA1 hash of the normalized name
	sha1Hash := sha1.Sum([]byte(name))

	// Convert the hash to a hex string
	hash := hex.EncodeToString(sha1Hash[:])

	return hash
}

func main33() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----
`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	fmt.Println(cert.Subject.String())
	hash := X509_NAME_hash_ex(cert.Subject.String())
	fmt.Println(hash)

	// fmt.Println(hex.EncodeToString(cert.RawSubject))

	// Calculate the MD5 hash of the subject's DER-encoded form

	// Convert the subject hash to a hex string
	h2 := sha1.Sum(cert.RawSubject[2:])
	hashString := hex.EncodeToString(h2[:])

	// Print the result
	fmt.Println(hashString)
}

func main6() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Calculate the hash (OpenSSL's -hash output)
	hash := calculateOpenSSLHash(cert.RawSubject)

	// Calculate the fingerprint (SHA1 hash of the certificate)
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprint := formatFingerprint(sha1Hash[:])

	// Print the results
	fmt.Println(hash)                             // This should match the -hash output from OpenSSL
	fmt.Println("SHA1 Fingerprint=", fingerprint) // This should match the -fingerprint output from OpenSSL
}

// Function to calculate OpenSSL style hash of the subject
func calculateOpenSSLHash(subject []byte) string {
	md5Sum := sha1.Sum(subject)
	// Take the first 4 bytes of the MD5 sum
	hash := md5Sum[:4]
	// Convert to an unsigned integer
	var result uint32
	for i := 0; i < 4; i++ {
		result |= uint32(hash[i]) << (8 * uint32(i))
	}
	return fmt.Sprintf("%08x", result)
}

// Function to format SHA1 fingerprint as needed
func formatFingerprint(hash []byte) string {
	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func main5() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Calculate the hash (MD5 hash of the DER-encoded subject)
	md5Hash := sha1.Sum(cert.RawSubject)
	hash := formatMD5Hash(md5Hash[:])

	// Calculate the fingerprint (SHA1 hash of the certificate)
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprint := formatFingerprint(sha1Hash[:])

	// Print the results
	fmt.Println("Hash:", hash)
	fmt.Println("Fingerprint:", fingerprint)
}

// Function to format MD5 hash as needed
func formatMD5Hash(hash []byte) string {
	var result strings.Builder
	for i, b := range hash {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(fmt.Sprintf("%02X", b))
	}
	return result.String()
}

func main4() {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Calculate the hash (OpenSSL's -hash output)
	hash := calculateOpenSSLHash(cert.RawSubject)

	// Calculate the fingerprint (SHA1 hash of the certificate)
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprint := make([]string, len(sha1Hash))
	for i, b := range sha1Hash {
		fingerprint[i] = fmt.Sprintf("%02X", b)
	}

	// Print the results
	fmt.Println("Hash:", hash)
	fmt.Println("Fingerprint:", strings.Join(fingerprint, ":"))
}

func main3() {
	// filename := "FILENAME" // Replace with your filename

	// Read the file
	//certPEM, err := ioutil.ReadFile(filename)
	//if err != nil {
	//	log.Fatalf("failed to read certificate file: %v", err)
	//}
	//
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgIUEG4GcmT8r86T8EdcfhdUwu3bm0EwDQYJKoZIhvcNAQEL
BQAwJzEUMBIGA1UEAwwLTVNTUUxTZXJ2ZXIxDzANBgNVBAoMBkt1YmVEQjAeFw0y
NDA1MjQxNjU1MzVaFw0yNTA1MjQxNjU1MzVaMCcxFDASBgNVBAMMC01TU1FMU2Vy
dmVyMQ8wDQYDVQQKDAZLdWJlREIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDtYJMnFsddWPMVWU5Cj9gmYbXbcUVMuuI//lAzt0pK8TlqquBPTvYJBFjS
12GZYE5k2n7kuJEaK1j7/rMurlRVJQKMfEEdL+yeqa8/6s8uSHis1GhY17ooqGju
Z22dSzWbx4b/qB9sU2BitwuqS62uB39jt4+L6tIZRQ11JSkc4GHqIChs78E0Ccrw
rr8VV+Hdx2fE6hRiQWiwj1hTfhemdzUP9TQm7k2OVHr5v32QmFyd3IMlYspQosaV
1FIITaBdQNrUZB5tQ0PzLPfnnSPfv6f2zRv9+gwsdf4M/EBKs3oCduBXFi1Vz0oE
3cWNLh9Gi4dTA8ZotcRrP8FnSySpAgMBAAGjUzBRMB0GA1UdDgQWBBSxoN+5ijbZ
yn1i17DqOD8DlmG32DAfBgNVHSMEGDAWgBSxoN+5ijbZyn1i17DqOD8DlmG32DAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDr9TmxFWyhbuZzai4/
OAhK/SAkn2rbh39GYf6Hgmsfag6w3eAaIIA7mMvy+KDbxALLQaMzNySyyCyCwmog
bn1EC3wDVnRRg2hh8d6Bo+0slrGIWlKNrjPcbcekojfT5QQ8ATa3vJSwpzuYky7t
Nzd2PXKtSMEdkFpmB93ALFIG8Euu34+ys4kUGNSFjRE7MqT+KxpR/Y+QzJ96vZHY
7zeJpeWMnLdpMnTh+jXXYxo/zfqYP9dJkBNqu4rqoaxUQXSpTOkgmIzH2jBCIKCG
bR7HWfkmyY2apMD2Y17C2MlFDQYOn0rHvsTPALuWur7M9VrIia5K0Y8cJkwobrgr
u1ox
-----END CERTIFICATE-----`)

	// Decode the PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the certificate")
	}

	// Parse the X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Calculate the hash (MD5 hash of the subject name)
	md5Hash := md5.Sum(cert.RawSubject)
	hash := hex.EncodeToString(md5Hash[:])
	// Format the hash to match OpenSSL output (separated by colons)
	hash = strings.ToLower(hash[:2] + ":" + hash[2:4] + ":" + hash[4:6] + ":" + hash[6:8])

	// Calculate the fingerprint (SHA1 hash of the certificate)
	sha1Hash := sha1.Sum(cert.Raw)
	fingerprint := make([]string, len(sha1Hash))
	for i, b := range sha1Hash {
		fingerprint[i] = fmt.Sprintf("%02X", b)
	}

	// Print the results
	fmt.Println("Hash:", hash)
	fmt.Println("Fingerprint:", strings.Join(fingerprint, ":"))
}

func main2() {
	doStuff("/tmp/workspace/appscode/static-assets")
}

func doStuff(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := filepath.Join(dir, entry.Name())
		fmt.Println(filename)

		//data, err := os.ReadFile(filename)
		//if err != nil {
		//	return err
		//}
		//fmt.Println()

		// io.Copy()
	}
	return nil
}

func copyFile(dst, src string) (int64, error) {
	srcStats, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !srcStats.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	return io.Copy(dstFile, srcFile)
}
