from pytube import YouTube
from rich import print
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

def download_video(url):
    try:
        yt = YouTube(url)
        streams = yt.streams.filter(file_extension='mp4')
        print(Panel(f"[bold blue]Video:[/bold blue] {yt.title}"))
        table = Table(title="Pilihan Resolusi", show_header=True, header_style="bold magenta")
        table.add_column("No.", style="dim", width=5)
        table.add_column("Resolusi", justify="center")
        table.add_column("MIME Type")

        for i, stream in enumerate(streams):
            table.add_row(str(i + 1), stream.resolution, stream.mime_type)

        print(table)

        while True:
            choice_str = Prompt.ask("[bold green]Pilih nomor resolusi (atau ketik 'quit', 'exit', 'keluar', atau 'change link video') [/bold green]")

            if choice_str.lower() in ["quit", "exit", "keluar"]:
                print(Panel(f"[bold yellow]Terimakasih.. sampai jumpa![/bold yellow]"))
                break

            elif choice_str.lower() == "change link video":
                return

            else:
                try:
                    choice = int(choice_str) - 1
                    if 0 <= choice < len(streams):
                        selected_stream = streams[choice]
                        if Confirm.ask(f"[bold yellow]Apakah Anda yakin ingin mengunduh {yt.title} dengan resolusi {selected_stream.resolution}?[/bold yellow]"):
                            print(f"[bold blue]Mengunduh : [/bold blue] {yt.title}")
                            selected_stream.download()
                            print(Panel(f"[bold green]Download selesai![/bold green]"))
                            break
                    else:
                        print("[bold red]Pilihan tidak valid. Silakan coba lagi.[/bold red]")
                except ValueError:
                    print("[bold red]Masukkan harus berupa angka atau perintah yang valid. Silakan coba lagi.[/bold red]")

    except Exception as e:
        print(Panel(f"[bold red]Terjadi kesalahan: {e}[/bold red]"))

if __name__ == "__main__":
    while True:
        url = Prompt.ask("[bold cyan]Masukkan tautan video YouTube (atau ketik 'quit', 'exit', 'keluar') [/bold cyan]")
        if url.lower() in ["quit", "exit", "keluar"]:
            print(Panel(f"[bold yellow]Terimakasih.. sampai jumpa![/bold yellow]"))
            break
        download_video(url)
