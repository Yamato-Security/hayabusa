# Clonado con Git

Puede clonar el repositorio con `git clone` mediante el siguiente comando y compilar el binario a partir del código fuente:

**Advertencia:** La rama main del repositorio es para fines de desarrollo, por lo que es posible que pueda acceder a nuevas funciones que aún no se han publicado oficialmente; sin embargo, puede haber errores, así que considérela inestable.

```bash
git clone https://github.com/Yamato-Security/hayabusa.git --recursive
```

> **Nota:** Si olvida usar la opción --recursive, la carpeta `rules`, que se gestiona como un submódulo de git, no se clonará.

Puede sincronizar la carpeta `rules` y obtener las reglas más recientes de Hayabusa con `git pull --recurse-submodules` o usar el siguiente comando:

```bash
hayabusa.exe update-rules
```

Si la actualización falla, es posible que deba renombrar la carpeta `rules` e intentarlo de nuevo.

>> Precaución: Al actualizar, las reglas y los archivos de configuración de la carpeta `rules` se reemplazan con las reglas y archivos de configuración más recientes del repositorio [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).
>> Cualquier cambio que realice en los archivos existentes se sobrescribirá, por lo que le recomendamos que haga copias de seguridad de los archivos que edite antes de actualizar.
>> Si está realizando un ajuste de niveles con `level-tuning`, vuelva a ajustar sus archivos de reglas después de cada actualización.
>> Si agrega reglas **nuevas** dentro de la carpeta `rules`, **no** se sobrescribirán ni eliminarán al actualizar.
