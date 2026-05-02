from pathlib import Path

from PIL import Image, ImageDraw


def main() -> None:
    output = Path("demo-image.png")
    image = Image.new("RGB", (900, 520), "#f7faf9")
    draw = ImageDraw.Draw(image)
    draw.rectangle((40, 40, 860, 480), outline="#0f766e", width=6)
    draw.rectangle((70, 82, 830, 170), fill="#0f766e")
    draw.text((100, 112), "Image Encryption System", fill="white")
    draw.text((100, 230), "Upload this sample image to test encryption.", fill="#1f2937")
    draw.text((100, 280), "Try AES-GCM first, then RSA hybrid mode.", fill="#1f2937")
    image.save(output)
    print(f"Created {output.resolve()}")


if __name__ == "__main__":
    main()

