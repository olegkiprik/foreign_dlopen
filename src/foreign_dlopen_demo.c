
void z_exit(int status);
void exec_elf(const char *file, int argc, char *argv[]);

#define DL_APP_DEFAULT "/bin/sleep"

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	const char *app;
	if (argc > 1 && argv[1] && argv[1][0]) {
		app = argv[1];
	} else {
		app = DL_APP_DEFAULT;
	}

	char *targv[] = { (char *)app, (char *)"x" };
	exec_elf(app, 2, targv);

	z_exit(0);
}



