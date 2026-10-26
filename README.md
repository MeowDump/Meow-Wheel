_This is my personal fork of the original repository, modified to fit my own needs and workflow._

## Requirements

- Magisk Official, KernelSU Official (or API compliant), or APatch
- MeowZygisk 508 or higher
- Android 7.1 or higher

> [!WARNING]
> Absolutely NO support will be given if requirements are NOT met.

## Support

Any question or issue related to Meow Wheel can be made on [Telegram](https://t.me/HelloMona)


## Usage

The only feature of Meow Wheel that requires setup is RVU (ReVanced Umount). ReVanced modules MUST include a `tw_config` file in their module folder with the following content:

```properties
module_type=revanced
allow_umount=true
```

Which will allow Meow Wheel to enumerate the amount of ReVanced modules -- hence amount of mounts it should find -- and umount them.


## License

Meow Wheel is licensed under [AGPLv3 License](LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/licenses/AGPL-3.0).

