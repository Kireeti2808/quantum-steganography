# 🌊🔐 Quantum-Inspired Hybrid Image Steganography & Watermarking

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Qiskit](https://img.shields.io/badge/Qiskit-Quantum-purple)
![OpenCV](https://img.shields.io/badge/OpenCV-Computer%20Vision-green)
![Security](https://img.shields.io/badge/Security-Cryptography-red)

## 📜 Project Overview
This project implements a secure, dual-layer image security system. It combines the high data capacity of **LSB (Least Significant Bit) Steganography** with the robustness of **DCT (Discrete Cosine Transform) Watermarking**, enhanced by **Quantum-Inspired Encoding**.

The goal is to solve the trade-off between **imperceptibility** (keeping the image looking original) and **robustness** (ensuring data survives attacks like JPEG compression).

### 🔑 Key Features
* **Hybrid Embedding:** Utilizes both Spatial domain (LSB) for secret messages and Frequency domain (DCT) for ownership watermarks.
* **Quantum-Inspired Encoding:** Uses **Qiskit** to simulate quantum superposition and entanglement, encoding data into a complex state before embedding.
* **Error Correction:** Implements **Reed-Solomon** codes and **Bit Repetition** to ensure watermark survival.
* **Attack Simulation:** Includes an automated pipeline to test resilience against JPEG compression (Quality 70-90).

---

## 👁️ Visual Results (Pipeline)
The system maintains high visual fidelity. As shown below, the modifications are invisible to the human eye despite containing hidden data and a robust watermark.

| 1. Original Input | 2. Stego Image (LSB) | 3. Watermarked (DCT) |
|:---:|:---:|:---:|
| ![Original](original.png) | ![Stego](stego.png) | ![Watermarked](watermarked.png) |
| **Raw Image** | **Contains Secret Text** | **Contains Owner ID** |

---

## 📊 Analysis Graphs
The following graphs demonstrate the performance of the system.

### 1. Imperceptibility Cost: PSNR Analysis
**Peak Signal-to-Noise Ratio (PSNR)** measures image fidelity.
* **Green Bars (LSB Only):** Extremely high PSNR (~90dB), indicating the changes are negligible.
* **Orange Bars (Hybrid DCT):** Lower PSNR (~38dB) due to robust frequency embedding, but still visually excellent (>35dB).

![PSNR Analysis](graph2.png)

### 2. Structural Similarity (SSIM)
**SSIM** measures how structurally similar the modified image is to the original (1.0 = Identical).
* **Blue Bars (LSB):** Perfect structural retention (1.0).
* **Pink Bars (DCT):** Slight reduction (~0.97), proving the watermark respects structural integrity.

![SSIM Analysis](graph3.png)

### 3. Robustness Test: Harshest Compression (Quality=70)
We subjected the images to aggressive JPEG compression (Quality 70).
* **Red/Orange Bars (LSB):** The fragile LSB message suffers high error rates (~45%), making the text unreadable.
* **Blue Bars (DCT):** The robust watermark has **0.00% Bit Error Rate**. The owner ID was recovered perfectly.

![BER Bar Chart](graph4.png)

### 4. Robustness Across Compression Levels
A trend line showing data survival across different JPEG qualities (70, 80, 90).
* **Dashed Line:** LSB fails consistently.
* **Solid Line:** DCT Watermark remains stable at 0% error, validating the Reed-Solomon strategy.

![BER Line Chart](graph5.png)

### 5. Comprehensive Metrics Overview
A combined visualization of all calculated metrics (PSNR, RMSE, SSIM, MAE, NCC) to provide a holistic view of image quality degradation vs. data security.

![All Metrics](graph6.png)

---

## 🛠️ Installation & Usage

### Prerequisites
* Python 3.8+
* Git

### 1. Clone the Repository
```bash
git clone [https://github.com/Kireeti2808/quantum-steganography.git](https://github.com/Kireeti2808/quantum-steganography.git)
cd quantum-steganography
