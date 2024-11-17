#!/usr/bin/python3

def read_file_and_convert_to_hex(file_path):
    try:
        with open(file_path, 'rb') as file:
            byte = file.read(1)  # Читаем по одному байту
            hex_output = []

            while byte:
                hex_output.append(byte.hex())  # Преобразуем байт в HEX
                byte = file.read(1)  # Читаем следующий байт

            # Записываем результат в файл
            with open('output.hex', 'w') as hex_file:
                hex_file.write(''.join(hex_output))  # Записываем HEX значения через пробел

        print("Конвертация завершена. Результат записан в 'output.hex'.")

    except Exception as e:
        print(f"Произошла ошибка: {e}")

# Укажите путь к вашему файлу
file_path = 'logs'  # Замените на путь к вашему файлу
read_file_and_convert_to_hex(file_path)

