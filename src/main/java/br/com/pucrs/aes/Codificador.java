package br.com.pucrs.aes;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import br.com.pucrs.arquivo.Texto;

public class Codificador {
	
	private String tipoDeInstancia;
	
	public Codificador(Texto texto) {
		if(texto.getOperacao().equals("CBC")) {
			tipoDeInstancia = "AES/CBC/PKCS5Padding";
		}
		if(texto.getOperacao().equals("CTR")) {
			tipoDeInstancia = "AES/CTR/NoPadding";
		}
	}

	public String codificar(String mensagem, String chave) throws Exception {		
		IvParameterSpec ivGerado = gerarIv();
		SecretKeySpec chaveSecreta = pegarChaveSecreta(chave);
		Cipher codificador = Cipher.getInstance(tipoDeInstancia);
		
		codificador.init(Cipher.ENCRYPT_MODE, chaveSecreta, ivGerado);
		byte[] mensagemCodificada = codificador.doFinal(converteParaArrayBytes(mensagem));
		
		return juntaParteIVComCodificada(mensagemCodificada, ivGerado);		
	}
	
	public IvParameterSpec gerarIv() {
		byte[] iv = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);

		return new IvParameterSpec(iv);
	}
	
	public static byte[] converteParaArrayBytes(String mensagem) {
		return DatatypeConverter.parseHexBinary(mensagem);
	}
	
	public String converteHexadecimalParaString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}
	
	public static SecretKeySpec pegarChaveSecreta(String chave) throws Exception {
		return new SecretKeySpec(converteParaArrayBytes(chave), "AES");
	}
	
	private String juntaParteIVComCodificada(byte[] mensagemCodificada, IvParameterSpec ivGerado) {		
		return converteHexadecimalParaString(ivGerado.getIV()) + converteHexadecimalParaString(mensagemCodificada);
	}
}
