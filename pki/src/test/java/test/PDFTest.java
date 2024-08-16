package test;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import bean.CertificadoUdemy;
import core.CertificateStore;
import core.PAdES_Firma;
import util.Constante;

public class PDFTest {
    public static void main(String[] args){
        try {
            CertificadoUdemy certificado = CertificateStore.getCertificateFromFile(Constante.CERTIFICADO, Constante.CLAVE);
            Path path = Paths.get(Constante.PDF);
            byte[] documento = Files.readAllBytes(path);
            //documento = PAdES_Firma.firmaPDFBasico(documento, certificado);
            documento = PAdES_Firma.firmarPdfAvanzado(documento, certificado);
            
            if (documento == null) {
                System.out.println(documento);
            }else{
                FileOutputStream out = new FileOutputStream(Constante.PDF_FIRMADO);
                out.write(documento);
                out.close();

                System.out.println("pdf firmado");
            }                    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
