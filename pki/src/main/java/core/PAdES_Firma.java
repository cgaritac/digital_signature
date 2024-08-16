package core;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateInfo.X500Name;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import bean.CertificadoUdemy;

public class PAdES_Firma {
    public static byte[] firmaPDFBasico(byte[] data, CertificadoUdemy certificado) throws Exception{
        try {
            Security.addProvider(new BouncyCastleProvider());

            PdfReader reader = new PdfReader(data);
            ByteArrayOutputStream nuevoDocumento = new ByteArrayOutputStream();

            PdfStamper stp = PdfStamper.createSignature(reader, nuevoDocumento, '\000', null, true);
            PdfSignatureAppearance sap = stp.getSignatureAppearance();

            sap.setReason("Firma Digital");
            sap.setLocation("Costa Rica");
            sap.setVisibleSignature(new Rectangle(100,100,350,200), 1, "sig");
            
            
            ExternalDigest digest = new BouncyCastleDigest();
            BouncyCastleProvider provider = new BouncyCastleProvider();
            ExternalSignature signature = new PrivateKeySignature(certificado.getPrivateKey(), DigestAlgorithms.SHA256, provider.getName());
            MakeSignature.signDetached(sap, digest, signature, certificado.getCertificateChain(),   null, null, null, 0, CryptoStandard.CMS);
            stp.close();

            return nuevoDocumento.toByteArray();

        } catch (Exception e){
            e.printStackTrace();            
        }
        return null;
    }

    public static byte[] firmarPdfAvanzado(byte[] dataDoc, CertificadoUdemy certificado) throws Exception {
        try {
            PdfReader reader = new PdfReader(dataDoc);
            ByteArrayOutputStream nuevoDocumento = new ByteArrayOutputStream();
            PdfStamper stamper = PdfStamper.createSignature(reader, nuevoDocumento, '\000', null, true);
            PdfSignatureAppearance sap = stamper.getSignatureAppearance();

            //Bloque para definir la firma digital            
            PdfSignature signature = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached")); // Investigar sobre el pkcs7
            signature.setReason("Firma Digital");
            signature.setLocation("Lima");

            Date fechaFirma = new Date();
            Calendar calendar = Calendar.getInstance();
            signature.setDate(new PdfDate(calendar));

            sap.setSignDate(calendar);
            sap.setCryptoDictionary(signature);

            //Bloque para definir la fima visible
            String firmado = "Firmado por " + CertificateInfo.getIssuerFields(certificado.getPublicCertificate()).getField("CN");
            String razon = "Motivo: " + "Firma Digital";
            String lugar = "Lugar: " + "Lima";
            SimpleDateFormat dateformatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss Z");
            String fecha = "Fecha: " + dateformatter.format(fechaFirma);
            String firmaH = firmado + '\n' + fecha + '\n' + razon + '\n' + lugar;
            sap.setLayer2Text(firmaH);
            sap.setVisibleSignature(new Rectangle(100, 100, 350, 200), 1, null);

            //Digest
            int contentEstimated = 8192;
            System.out.println(reader.getFileLength());
            HashMap<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
            sap.preClose(exc);
            
            InputStream data = sap.getRangeStream();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[contentEstimated];
            int n;
            while ((n = data.read(buf)) > 0){
                messageDigest.update(buf, 0, n);                
            }

            byte[] hash = messageDigest.digest();
            Calendar calendario = Calendar.getInstance();

            //Firma
            PdfPKCS7 sgn = new PdfPKCS7(certificado.getPrivateKey(), certificado.getCertificateChain(),"SHA-256", null, null, false);
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, CryptoStandard.CMS);
            sgn.update(sh, 0, sh.length);
            byte[] encodedSig = sgn.getEncodedPKCS7(hash, null, null, null,  CryptoStandard .CMS);

            //Adicion al archivo pdf
            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
            PdfDictionary pdfDic = new PdfDictionary();
            pdfDic.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            sap.close(pdfDic);

            reader.close();
            nuevoDocumento.flush();
            nuevoDocumento.close();

            return nuevoDocumento.toByteArray();

            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
