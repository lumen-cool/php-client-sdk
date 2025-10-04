# Contributing Guidelines

Thank you for your interest in contributing to this project!

We welcome community contributions. Please follow these simple steps when submitting changes.

## How to Contribute

1. **Fork** the repository and create a new branch for your changes.
2. **Make your changes** and ensure that all tests pass.
3. **Submit a Pull Request (PR)** with a clear description of your contribution.
4. **Include the Contributor License Notice** in your PR description (see below).

> **Note:** Contributions are licensed to the maintainers, specifically **Anikeen Holding UG (haftungsbeschränkt)**,
> under both AGPLv3 and Apache 2.0 for use in commercial or relicensed versions.

### Example: Contributor License Notice

Please include the following text when opening a pull request:

> **Contributor License Notice**
>
> By submitting this pull request, I confirm that:
>
> 1. **Ownership:** I am the owner of these contributions and have the right to submit them.
> 2. **Licensing to Maintainers:** I license my contributions to the project maintainers under **both**:
>    - The **GNU Affero General Public License v3 (AGPLv3)**, and
>    - The **Apache License 2.0** (for use in commercial or relicensed versions).
> 3. **Public License:** I understand that the public version of the project remains licensed under **AGPLv3**, and that the **Apache 2.0 license applies only to the maintainers**, not to the general public.
> 4. **Relicensing Permission:** I grant the project maintainers the right to **relicense my contributions under other terms** used by the project, including for commercial editions.

## Code of Conduct

Please be respectful and constructive in all interactions.  
We aim to maintain a welcoming and collaborative environment.

## Coding Style

Anikeen follows the PSR-2 coding standard and the PSR-4 autoloading standard.

### PHPDoc

Below is an example of a valid Anikeen documentation block.

```php
/**
 * Register a binding with the container.
 *
 * @param string|array $abstract
 * @param \Closure|string|null $concrete
 * @param bool $shared
 * @return void
 *
 * @throws \Exception
 */
public function bind($abstract, $concrete = null, $shared = false)
{
    // ...
}
```

When the `@param` or `@return` attributes are redundant due to the use of native types, they can be removed:

```php
/**
 * Execute the job.
 */
public function handle(AudioProcessor $processor): void
{
    //
}
```

However, when the native type is generic, please specify the generic type through the use of the `@param` or `@return`
attributes:

```php
/**
 * Get the attachments for the message.
 *
 * @return array<int, \Anikeen\Example\Attachment>
 */
public function attachments(): array
{
    return [
        Attachment::fromStorage('/path/to/file'),
    ];
}
```

## Questions or Support

If you have questions about contributing, open a discussion or contact the maintainers before submitting a PR.