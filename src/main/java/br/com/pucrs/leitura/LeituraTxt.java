package br.com.pucrs.leitura;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import br.com.pucrs.arquivo.Texto;



public class LeituraTxt {
	
	public LeituraTxt() {}

	public Texto leitura(String nome) {
		Texto texto = new Texto();
		String linha = "";
		
		try (FileReader leitorArquivo = new FileReader(nome);
			BufferedReader leituraBuffer = new BufferedReader(leitorArquivo)){						

			while ((linha = leituraBuffer.readLine()) != null) {
				if(linha.contains("CBC key:")) {
					texto.setOperacao("CBC");
					texto.setChave(linha.substring(8));
				}
				if(linha.contains("CTR key:")) {
					texto.setOperacao("CTR");
					texto.setChave(linha.substring(8));
				}				
				if(linha.contains("CTR Plaintext:")) {
					texto.setTipo("Plaintext");
					texto.setBloco(linha.substring(14));
				}
				if(linha.contains("CTR Ciphertext:")) {
					texto.setTipo("Ciphertext");
					texto.setBloco(linha.substring(15));
				}
				if(linha.contains("CBC Ciphertext:")) {
					texto.setTipo("Ciphertext");
					texto.setBloco(linha.substring(15));
				}
				if(linha.contains("CBC Plaintext:")) {
					texto.setTipo("Plaintext");
					texto.setBloco(linha.substring(14));
				}
			}			
			
		} catch (FileNotFoundException ex) {
			System.out.println("Não foi encontrado o arquivo:  " + nome);
		} catch (IOException ex) {
			System.out.println("Erro na leitura do arquivo txt: " + nome);
		}
		
		return texto;

	}


}