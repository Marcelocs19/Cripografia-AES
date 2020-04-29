package br.com.pucrs;

import java.util.Scanner;

import br.com.pucrs.aes.Codificador;
import br.com.pucrs.aes.Decifrador;
import br.com.pucrs.arquivo.Texto;
import br.com.pucrs.leitura.LeituraTxt;

public class App {
	public static void main(String[] args) {
		try (Scanner teclado = new Scanner(System.in)) {

			LeituraTxt leitura = new LeituraTxt();

			System.out.println("Digite o no do arquivo txt: ");

			String nomeArquivo = teclado.nextLine();

			Texto texto = leitura.leitura(nomeArquivo);

			Codificador codificador = new Codificador(texto);

			Decifrador decifrador = new Decifrador(texto);

			if(texto.getTipo().equals("Ciphertext")) {
				System.out.println("Mensagem decifrada: " + decifrador.decodificarMensagem(texto.getBloco(), texto.getChave()));
			}
			if(texto.getTipo().equals("Plaintext")) {
				String encriptarMensagem = codificador.encriptarMensagem(texto.getBloco(), texto.getChave());
				System.out.println("Mensagem encriptada: " + encriptarMensagem);
				
				String decodificarMensagem = decifrador.decodificarMensagem(encriptarMensagem, texto.getChave());
				System.out.println("Mensagem decifrada: " + decodificarMensagem);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
