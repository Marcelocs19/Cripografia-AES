package br.com.pucrs.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import br.com.pucrs.arquivo.Texto;

public class Decifrador {
	
	private String tipoDeInstancia;
	
	private static final String INSTANCIA_CBC = "AES/CBC/PKCS5Padding";
	
	private static final String INSTANCIA_CTR = "AES/CTR/NoPadding";
	
	public Decifrador(Texto texto) {
		if(texto.getOperacao().equals("CBC")) {
			tipoDeInstancia = INSTANCIA_CBC;
		} 
		if(texto.getOperacao().equals("CTR")) {
			tipoDeInstancia = INSTANCIA_CTR;
		}
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}
	
	public String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}
	
	public IvParameterSpec extrairIvDeMensagemCodificada(byte[] mensagemCodificada) {

		byte[] iv = new byte[16];
		System.arraycopy(mensagemCodificada, 0, iv, 0, iv.length);

		return new IvParameterSpec(iv);
	}

	public byte[] extrairMensagemCodificadaSemIv(byte[] mensagemCodificada) {

		int tamanhoMensagemCodificadaSemIv = mensagemCodificada.length - 16;
		byte[] mensagemCodificadaSemIv = new byte[tamanhoMensagemCodificadaSemIv];
		System.arraycopy(mensagemCodificada, 16, mensagemCodificadaSemIv, 0, tamanhoMensagemCodificadaSemIv);
		
		return mensagemCodificadaSemIv;
	}

	public static SecretKeySpec pegarChaveSecreta(String chave) throws Exception {
		return new SecretKeySpec(toByteArray(chave), "AES");
	}	
	
	public String decodificarMensagem(String mensagemCodificada, String chave) throws Exception {
		
		byte[] mensagemCodificadaBytes = toByteArray(mensagemCodificada);

		IvParameterSpec ivExtraido = extrairIvDeMensagemCodificada(mensagemCodificadaBytes);
		SecretKeySpec chaveSecreta = pegarChaveSecreta(chave);
		byte[] mensagemCodificadaSemIv = extrairMensagemCodificadaSemIv(mensagemCodificadaBytes);
		Cipher decodificador = Cipher.getInstance(tipoDeInstancia);

		decodificador.init(Cipher.DECRYPT_MODE, chaveSecreta, ivExtraido);
		byte[] mensagemDecodificada = decodificador.doFinal(mensagemCodificadaSemIv); 
		
		return new String(mensagemDecodificada);
	}

}
