# Tujuan Utama

## Perburuan Ancaman dan DFIR Skala Perusahaan

Saat ini Hayabusa memiliki lebih dari 4000 aturan Sigma dan lebih dari 170 aturan deteksi bawaan Hayabusa dengan aturan baru yang ditambahkan secara berkala.
Hayabusa dapat digunakan untuk perburuan ancaman proaktif skala perusahaan serta DFIR (Digital Forensics and Incident Response) secara gratis dengan [Hayabusa artifact](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) dari [Velociraptor](https://docs.velociraptor.app/).
Dengan menggabungkan kedua alat sumber terbuka ini, Anda pada dasarnya dapat secara retroaktif mereproduksi SIEM ketika tidak ada pengaturan SIEM di lingkungan tersebut.
Anda dapat mempelajari cara melakukannya dengan menonton panduan Velociraptor dari [Eric Capuano](https://twitter.com/eric_capuano) [di sini](https://www.youtube.com/watch?v=Q1IoGX--814).

## Pembuatan Linimasa Forensik yang Cepat

Analisis log peristiwa Windows secara tradisional merupakan proses yang sangat panjang dan melelahkan karena log peristiwa Windows 1) berada dalam format data yang sulit dianalisis dan 2) sebagian besar datanya berupa derau dan tidak berguna untuk investigasi.
Tujuan Hayabusa adalah mengekstrak hanya data yang berguna dan menyajikannya dalam format seringkas mungkin yang mudah dibaca, yang dapat digunakan tidak hanya oleh analis terlatih profesional tetapi juga oleh setiap administrator sistem Windows.
Hayabusa berharap dapat membuat analis menyelesaikan 80% pekerjaan mereka dalam 20% waktu jika dibandingkan dengan analisis log peristiwa Windows tradisional.

![DFIR Timeline](../assets/doc/DFIR-TimelineCreation-EN.png)
