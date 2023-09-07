package selfsignedcertgen

import (
	"bytes"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/cshu/golangrs"
	"math/big"
	"time"
)

func Gen() (certandkey []byte, err error) {
	//priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 20000),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if nil == cert {
		return nil, errors.New("ERR pem encode")
	}
	//ecpk, err := x509.MarshalECPrivateKey(priv)
	//if err != nil {
	//	return nil, err
	//}
	//thekey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecpk})
	//if nil == thekey {
	//	return nil, errors.New("ERR pem encode")
	//}
	rsapk := x509.MarshalPKCS1PrivateKey(priv)
	thekey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsapk})
	if nil == thekey {
		return nil, errors.New("ERR pem encode")
	}
	var retval bytes.Buffer
	golangrs.WriteUint32ToBytesBuffer(&retval, uint32(len(cert)))
	retval.Write(cert)
	retval.Write(thekey)
	return retval.Bytes(), nil
}
