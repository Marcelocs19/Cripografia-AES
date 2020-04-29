package br.com.pucrs.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import br.com.pucrs.arquivo.Texto;

public class Decifrador {
	
	private String tipoDeInstancia;
	
	public Decifrador(Texto texto) {
		if(texto.getOperacao().equals("CBC")) {
			tipoDeInstancia = "AES/CBC/PKCS5Padding";
		} 
		if(texto.getOperacao().equals("CTR")) {
			tipoDeInstancia = "AES/CTR/NoPadding";
		}
	}
	
	public String decodificar(String mensagem, String chave) throws Exception {		
		IvParameterSpec ivExtraido = getIvMensagemCodificada(converteParaArrayBytes(mensagem));
		SecretKeySpec chaveSecreta = pegarChaveSecreta(chave);
		Cipher decodificador = Cipher.getInstance(tipoDeInstancia);

		decodificador.init(Cipher.DECRYPT_MODE, chaveSecreta, ivExtraido);
		byte[] mensagemDecodificada = decodificador.doFinal(getMensagemCodificadaSemIv(converteParaArrayBytes(mensagem))); 
		
		return new String(mensagemDecodificada);
	}

	public static byte[] converteParaArrayBytes(String mensagem) {
		return DatatypeConverter.parseHexBinary(mensagem);
	}
	
	public IvParameterSpec getIvMensagemCodificada(byte[] mensagemCodificada) {
		byte[] iv = new byte[16];
		System.arraycopy(mensagemCodificada, 0, iv, 0, iv.length);

		return new IvParameterSpec(iv);
	}

	public byte[] getMensagemCodificadaSemIv(byte[] mensagemCodificada) {

		int tamanhoMensagemCodificadaSemIv = mensagemCodificada.length - 16;
		byte[] mensagemCodificadaSemIv = new byte[tamanhoMensagemCodificadaSemIv];
		System.arraycopy(mensagemCodificada, 16, mensagemCodificadaSemIv, 0, tamanhoMensagemCodificadaSemIv);
		
		return mensagemCodificadaSemIv;
	}

	public static SecretKeySpec pegarChaveSecreta(String chave) throws Exception {
		return new SecretKeySpec(converteParaArrayBytes(chave), "AES");
	}	
	


}
