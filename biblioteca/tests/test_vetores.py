"""
Testes com vetores oficiais (Known Answer Tests).

Comprovam que as implementações produzem exatamente os mesmos resultados das
especificações:
    * DES  - exemplo clássico de Grabbe / FIPS 46 (chave 133457799BBCDFF1)
    * AES  - FIPS-197, apêndice C (AES-128/192/256) e NIST SP 800-38A (CBC, CTR)
    * RC5  - vetores do artigo original de Rivest (RC5-32/12/16)

Executar a partir da pasta `biblioteca`:
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from securedocs_crypto import (AES, DES, RC5, ArquivoCorrompido, TripleDES, cbc_decrypt,  # noqa: E402
                               cbc_encrypt, cifrar_bytes, ctr_crypt, decifrar_bytes, ecb_decrypt,
                               ecb_encrypt)

h = bytes.fromhex


class TestDES(unittest.TestCase):
    def test_vetor_classico(self):
        cifra = DES(h("133457799BBCDFF1"))
        self.assertEqual(cifra.encrypt_block(h("0123456789ABCDEF")), h("85E813540F0AB405"))
        self.assertEqual(cifra.decrypt_block(h("85E813540F0AB405")), h("0123456789ABCDEF"))

    def test_vetor_nist_sp800_17(self):
        # Tabela de "variable plaintext" do NIST SP 800-17, chave 0101...01
        cifra = DES(h("0101010101010101"))
        self.assertEqual(cifra.encrypt_block(h("8000000000000000")), h("95F8A5E5DD31D900"))

    def test_3des_com_chaves_iguais_equivale_a_des(self):
        k = h("133457799BBCDFF1")
        self.assertEqual(TripleDES(k * 3).encrypt_block(h("0123456789ABCDEF")), h("85E813540F0AB405"))


class TestAES(unittest.TestCase):
    PT = h("00112233445566778899aabbccddeeff")

    def test_fips197_aes128(self):
        cifra = AES(h("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(cifra.encrypt_block(self.PT), h("69c4e0d86a7b0430d8cdb78070b4c55a"))
        self.assertEqual(cifra.decrypt_block(h("69c4e0d86a7b0430d8cdb78070b4c55a")), self.PT)

    def test_fips197_aes192(self):
        cifra = AES(h("000102030405060708090a0b0c0d0e0f1011121314151617"))
        self.assertEqual(cifra.encrypt_block(self.PT), h("dda97ca4864cdfe06eaf70a0ec0d7191"))

    def test_fips197_aes256(self):
        cifra = AES(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        self.assertEqual(cifra.encrypt_block(self.PT), h("8ea2b7ca516745bfeafc49904b496089"))
        self.assertEqual(cifra.decrypt_block(h("8ea2b7ca516745bfeafc49904b496089")), self.PT)

    def test_sbox(self):
        from securedocs_crypto.aes import SBOX
        self.assertEqual((SBOX[0x00], SBOX[0x01], SBOX[0x53], SBOX[0xFF]), (0x63, 0x7C, 0xED, 0x16))

    def test_sp800_38a_cbc(self):
        cifra = AES(h("2b7e151628aed2a6abf7158809cf4f3c"))
        iv = h("000102030405060708090a0b0c0d0e0f")
        _, c = cbc_encrypt(cifra, h("6bc1bee22e409f96e93d7e117393172a"), iv)
        self.assertEqual(c[:16], h("7649abac8119b246cee98e9b12e9197d"))

    def test_sp800_38a_ctr(self):
        cifra = AES(h("2b7e151628aed2a6abf7158809cf4f3c"))
        c = ctr_crypt(cifra, h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), h("6bc1bee22e409f96e93d7e117393172a"))
        self.assertEqual(c, h("874d6191b620e3261bef6864990db6ce"))


class TestRC5(unittest.TestCase):
    def test_rivest_1(self):
        cifra = RC5(bytes(16))
        self.assertEqual(cifra.encrypt_block(bytes(8)), h("21A5DBEE154B8F6D"))

    def test_rivest_2(self):
        cifra = RC5(h("915F4619BE41B2516355A50110A9CE91"))
        self.assertEqual(cifra.encrypt_block(h("21A5DBEE154B8F6D")), h("F7C013AC5B2B8952"))
        self.assertEqual(cifra.decrypt_block(h("F7C013AC5B2B8952")), h("21A5DBEE154B8F6D"))

    def test_rivest_3(self):
        cifra = RC5(h("783348E75AEB0F2FD7B169BB8DC16787"))
        self.assertEqual(cifra.encrypt_block(h("F7C013AC5B2B8952")), h("2F42B3B70369FC92"))

    def test_outros_parametros_ida_e_volta(self):
        for w in (16, 32, 64):
            cifra = RC5(os.urandom(10), rodadas=20, tamanho_palavra=w)
            bloco = os.urandom(cifra.block_size)
            self.assertEqual(cifra.decrypt_block(cifra.encrypt_block(bloco)), bloco)


class TestModosEArquivo(unittest.TestCase):
    DADOS = b"Contrato TechSecure n. 2026/031 - valor R$ 1.250.000,00 " * 7

    def test_ida_e_volta_todos_os_algoritmos(self):
        for cifra in (DES(os.urandom(8)), TripleDES(os.urandom(24)), RC5(os.urandom(16)), AES(os.urandom(32))):
            with self.subTest(cifra=cifra.nome):
                self.assertEqual(ecb_decrypt(cifra, ecb_encrypt(cifra, self.DADOS)), self.DADOS)
                iv, c = cbc_encrypt(cifra, self.DADOS)
                self.assertEqual(cbc_decrypt(cifra, iv, c), self.DADOS)
                n = os.urandom(cifra.block_size)
                self.assertEqual(ctr_crypt(cifra, n, ctr_crypt(cifra, n, self.DADOS)), self.DADOS)

    def test_arquivo_ida_e_volta(self):
        pacote = cifrar_bytes(self.DADOS, "senha-forte")
        self.assertNotIn(b"Contrato", pacote)
        self.assertEqual(decifrar_bytes(pacote, "senha-forte"), self.DADOS)

    def test_mesma_entrada_gera_saidas_diferentes(self):
        self.assertNotEqual(cifrar_bytes(self.DADOS, "s"), cifrar_bytes(self.DADOS, "s"))

    def test_adulteracao_detectada(self):
        pacote = bytearray(cifrar_bytes(self.DADOS, "senha-forte"))
        pacote[60] ^= 0x01
        with self.assertRaises(ArquivoCorrompido):
            decifrar_bytes(bytes(pacote), "senha-forte")

    def test_senha_errada(self):
        with self.assertRaises(ArquivoCorrompido):
            decifrar_bytes(cifrar_bytes(self.DADOS, "certa"), "errada")


if __name__ == "__main__":
    unittest.main(verbosity=2)
