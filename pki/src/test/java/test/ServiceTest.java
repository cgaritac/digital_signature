package test;

import java.util.List;

import bean.CertificadoUdemy;
import core.CertificateStore;
import util.Constante;

public class ServiceTest {

    public static void main(String[] args) {
        try {
            // CertificadoUdemy certificado = CertificateStore.getCertificateFromFile(Constante.CERTIFICADO, Constante.CLAVE);
            // System.out.println(certificado.getAlias());
            // System.out.println("--------------------------------------------");
            // System.out.println(certificado.getPrivateKey().getAlgorithm());
            // System.out.println("--------------------------------------------");
            // System.out.println(certificado.getPublicCertificate().toString());

             List<CertificadoUdemy> listCertificadoUdemy = CertificateStore.listCertificateFromStore();
            for(CertificadoUdemy certificadoUdemy : listCertificadoUdemy){
                System.out.println(certificadoUdemy.getAlias());
                System.out.println(certificadoUdemy.getPublicCertificate().getIssuerDN());
                System.out.println(certificadoUdemy.getPublicCertificate().getNotAfter());
                System.out.println("--------------------------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
