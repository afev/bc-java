package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.impl.AbstractTlsSecretKey;

import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class JceTlsSecretKey
    extends AbstractTlsSecretKey {

    protected final JcaTlsCrypto crypto;

    public JceTlsSecretKey(JcaTlsCrypto crypto, SecretKey key)
    {
        super(key);

        this.crypto = crypto;
    }

    @Override
    protected AbstractTlsCrypto getCrypto()
    {
        return crypto;
    }

    public SecretKey getSecretKey()
    {
        return secretKey;
    }

    @Override
    public synchronized TlsSecret deriveUsingPRF(int prfAlgorithm, String label, byte[] seed, int length)
    {
        switch (label) {
            case ExporterLabel.key_expansion: {
                // If call is from TlsImplUtils#calculateKeyBlock do nothing: keys are already created earlier in generateKeyForTls().
                return new JceTlsSecret(crypto, new byte[length]);
            }
            case ExporterLabel.client_finished:
            case ExporterLabel.server_finished: {
                // If call is from TlsUtils#calculateVerifyData calculate finished message.
                try
                {
                    String algorithm = "GOST3412_2015_K";
                    SecretKeyFactory secretKeyFactory = crypto.getHelper().createSecretKeyFactory(algorithm + "_MASTER_KEY");
                    secretKeyFactory.generateSecret(new SecretKeySpec(seed, "SEED")); // 1: pass the seed
                    secretKeyFactory.generateSecret(new SecretKeySpec(Strings.toByteArray(label), "LABEL")); // 2: pass the label
                    SecretKeySpec verifyDataSpec = (SecretKeySpec) secretKeyFactory.getKeySpec(secretKey, SecretKeySpec.class); // 3. require computing of verify data
                    return new JceTlsSecret(crypto, verifyDataSpec.getEncoded());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            default: {
                // Creating a master secret.
                try
                {
                    String algorithm = "GOST3412_2015_K";
                    SecretKeyFactory secretKeyFactory = crypto.getHelper().createSecretKeyFactory(algorithm + "_MASTER_KEY");
                    secretKeyFactory.generateSecret(new SecretKeySpec(seed, "SEED")); // 1: pass the seed
                    SecretKey masterSecret = secretKeyFactory.translateKey(secretKey); // 2: create a master-secret from the pre-master-secret
                    return new JceTlsSecretKey(crypto, masterSecret);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    public synchronized JceTlsSecretKey generateKeyForTls(TlsCryptoParameters cryptoParams, boolean isCipher, boolean isWrite, byte[] iv)
    {
        boolean isServer = cryptoParams.isServer();
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        byte[] clientRnd = securityParameters.getClientRandom();
        byte[] serverRnd = securityParameters.getServerRandom();
        byte[] seed = TlsUtils.concat(clientRnd, serverRnd);
        try
        {
            String keyAlgorithm = "GOST3412_2015_K" + (isCipher ? "_TLS_CIPHER_KEY" : "_TLS_MAC_KEY");
            SecretKeyFactory secretKeyFactory = crypto.getHelper().createSecretKeyFactory(keyAlgorithm);
            secretKeyFactory.generateSecret(new SecretKeySpec(seed, "SEED")); // 1: pass the seed
            secretKeyFactory.generateSecret(new SecretKeySpec(new byte[] { (byte)(isServer ? 1 : 0) }, "SERVER")); // 2: pseudo-boolean: is for server
            secretKeyFactory.generateSecret(new SecretKeySpec(new byte[] { (byte)(isWrite ? 1 : 0) }, "WRITE")); // 3: pseudo-boolean: is for write
            SecretKey generatedKey = secretKeyFactory.translateKey(secretKey); // 5: create base key from master-secret
            if (isCipher)
            {
                SecretKeySpec ivSpec = (SecretKeySpec) secretKeyFactory.getKeySpec(generatedKey, SecretKeySpec.class); // 6: require an IV for cipher
                System.arraycopy(ivSpec.getEncoded(), 0, iv, 0, ivSpec.getEncoded().length);
            }
            return new JceTlsSecretKey(crypto, generatedKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized TlsSecret hkdfExpand(int cryptoHashAlgorithm, byte[] info, int length)
    {
        return null;
    }

    @Override
    public synchronized TlsSecret hkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm)
    {
        return null;
    }

}
